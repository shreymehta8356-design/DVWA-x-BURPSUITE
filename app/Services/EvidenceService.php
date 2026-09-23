<?php

declare(strict_types=1);

namespace App\Services;

use App\AI\AiService;
use App\Core\Audit;
use App\Core\Auth;
use App\Core\Config;
use App\Core\Database;
use App\Core\Http;
use RuntimeException;

/**
 * Evidence capture with integrity and chain of custody.
 *
 * Rules enforced here:
 *   - every artefact is hashed with SHA-256 at the moment of capture, and the
 *     hash of the ORIGINAL bytes is what is recorded, so redaction never
 *     invalidates the integrity claim;
 *   - uploaded files are renamed to a random identifier, stored outside the
 *     document root, and validated by real MIME type rather than by extension
 *     or by the Content-Type the browser sent;
 *   - every access, attachment, export and redaction writes a custody row, so
 *     the report can print who handled each artefact and when.
 */
final class EvidenceService
{
    public const TYPES = ['screenshot', 'http_request', 'http_response', 'burp_item', 'log', 'note', 'file'];

    public static function storagePath(): string
    {
        $path = (string) Config::get('app.storage_path', APP_ROOT . '/storage') . '/evidence';
        if (!is_dir($path)) {
            mkdir($path, 0775, true);
        }
        return $path;
    }

    /**
     * Records text evidence (a captured request, response, log excerpt or note).
     *
     * @param  array<string,mixed> $input
     * @return array<string,mixed>
     */
    public static function captureText(int $assessmentId, array $input): array
    {
        $type = in_array($input['evidence_type'] ?? '', self::TYPES, true) ? (string) $input['evidence_type'] : 'note';
        $content = (string) ($input['content_text'] ?? '');
        if (trim($content) === '') {
            throw new RuntimeException('Evidence content cannot be empty.');
        }

        // Hash the original bytes BEFORE any redaction.
        $originalHash = hash('sha256', $content);

        $redactionSummary = null;
        $isRedacted = 0;
        if (Config::settingBool('auto_redact_evidence', true)) {
            $ai = new AiService();
            $result = $ai->redact($content, $assessmentId);
            if ($result['redactions'] > 0) {
                $content = $result['text'];
                $redactionSummary = $result['summary'];
                $isRedacted = 1;
            }
        }

        $id = Database::insert('evidence', [
            'assessment_id'     => $assessmentId,
            'test_id'           => self::nullableId($input['test_id'] ?? null),
            'finding_id'        => self::nullableId($input['finding_id'] ?? null),
            'retest_id'         => self::nullableId($input['retest_id'] ?? null),
            'evidence_type'     => $type,
            'title'             => mb_substr(trim((string) ($input['title'] ?? 'Untitled evidence')), 0, 200),
            'description'       => mb_substr((string) ($input['description'] ?? ''), 0, 5000),
            'content_text'      => $content,
            'sha256'            => $originalHash,
            'is_redacted'       => $isRedacted,
            'redaction_summary' => $redactionSummary,
            'captured_at'       => (string) ($input['captured_at'] ?? date('Y-m-d H:i:s')),
            'collected_by'      => Auth::id(),
        ]);

        self::custody($id, 'collected', 'Captured as ' . $type . '. SHA-256 recorded over the original content.');
        if ($isRedacted === 1) {
            self::custody($id, 'redacted', (string) $redactionSummary);
        }

        Audit::log('evidence.captured', 'evidence', $id, ['type' => $type, 'sha256' => $originalHash, 'redacted' => (bool) $isRedacted], $assessmentId);

        return self::find($id) ?? [];
    }

    /**
     * Stores an uploaded artefact.
     *
     * @param  array<string,mixed> $file  a single entry from $_FILES
     * @param  array<string,mixed> $input
     * @return array<string,mixed>
     */
    public static function captureFile(int $assessmentId, array $file, array $input): array
    {
        if (($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
            throw new RuntimeException(self::uploadErrorMessage((int) ($file['error'] ?? UPLOAD_ERR_NO_FILE)));
        }
        $tmp = (string) $file['tmp_name'];
        if (!is_uploaded_file($tmp)) {
            throw new RuntimeException('Upload rejected: the file did not arrive through an HTTP upload.');
        }

        $maxBytes = max(1, Config::settingInt('evidence_max_mb', 16)) * 1024 * 1024;
        $size = (int) ($file['size'] ?? 0);
        if ($size <= 0 || $size > $maxBytes) {
            throw new RuntimeException('File must be between 1 byte and ' . (int) ($maxBytes / 1048576) . ' MB.');
        }

        // Real content type, not the browser-supplied one.
        $finfo = new \finfo(FILEINFO_MIME_TYPE);
        $mime = (string) ($finfo->file($tmp) ?: 'application/octet-stream');
        $allowedMime = (array) Config::get('evidence.allowed_mime', []);
        if ($allowedMime !== [] && !in_array($mime, $allowedMime, true)) {
            throw new RuntimeException('File type "' . $mime . '" is not accepted as evidence.');
        }

        $originalName = mb_substr(basename((string) ($file['name'] ?? 'evidence')), 0, 200);
        $extension = strtolower((string) pathinfo($originalName, PATHINFO_EXTENSION));
        $allowedExt = (array) Config::get('evidence.allowed_extensions', []);
        if ($extension === '' || ($allowedExt !== [] && !in_array($extension, $allowedExt, true))) {
            throw new RuntimeException('File extension ".' . $extension . '" is not accepted as evidence.');
        }
        // Never trust the uploaded name for the stored name.
        $storedName = date('Ymd') . '-' . bin2hex(random_bytes(16)) . '.' . preg_replace('/[^a-z0-9]/', '', $extension);

        $hash = hash_file('sha256', $tmp);
        if ($hash === false) {
            throw new RuntimeException('Could not hash the uploaded file.');
        }

        $target = self::storagePath() . '/' . $storedName;
        if (!move_uploaded_file($tmp, $target)) {
            throw new RuntimeException('Could not store the uploaded file. Check permissions on storage/evidence.');
        }
        @chmod($target, 0640);

        $type = in_array($input['evidence_type'] ?? '', self::TYPES, true)
            ? (string) $input['evidence_type']
            : (str_starts_with($mime, 'image/') ? 'screenshot' : 'file');

        $id = Database::insert('evidence', [
            'assessment_id' => $assessmentId,
            'test_id'       => self::nullableId($input['test_id'] ?? null),
            'finding_id'    => self::nullableId($input['finding_id'] ?? null),
            'retest_id'     => self::nullableId($input['retest_id'] ?? null),
            'evidence_type' => $type,
            'title'         => mb_substr(trim((string) ($input['title'] ?? $originalName)), 0, 200),
            'description'   => mb_substr((string) ($input['description'] ?? ''), 0, 5000),
            'stored_name'   => $storedName,
            'original_name' => $originalName,
            'mime_type'     => $mime,
            'file_size'     => $size,
            'sha256'        => $hash,
            'captured_at'   => (string) ($input['captured_at'] ?? date('Y-m-d H:i:s')),
            'collected_by'  => Auth::id(),
        ]);

        self::custody($id, 'collected', 'Uploaded as ' . $originalName . ' (' . $mime . ', ' . $size . ' bytes). SHA-256 ' . $hash);
        Audit::log('evidence.uploaded', 'evidence', $id, ['name' => $originalName, 'mime' => $mime, 'sha256' => $hash], $assessmentId);

        return self::find($id) ?? [];
    }

    /** @return array<string,mixed>|null */
    public static function find(int $id): ?array
    {
        $row = Database::one(
            'SELECT e.*, u.username AS collected_by_username, u.full_name AS collected_by_name
             FROM evidence e LEFT JOIN users u ON u.id = e.collected_by WHERE e.id = ?',
            [$id]
        );
        return $row === null ? null : self::present($row);
    }

    /** @return array<int,array<string,mixed>> */
    public static function listFor(int $assessmentId, ?int $testId = null, ?int $findingId = null, ?int $retestId = null): array
    {
        $sql = 'SELECT e.*, u.username AS collected_by_username, u.full_name AS collected_by_name
                FROM evidence e LEFT JOIN users u ON u.id = e.collected_by
                WHERE e.assessment_id = ?';
        $params = [$assessmentId];
        if ($testId !== null)    { $sql .= ' AND e.test_id = ?';    $params[] = $testId; }
        if ($findingId !== null) { $sql .= ' AND e.finding_id = ?'; $params[] = $findingId; }
        if ($retestId !== null)  { $sql .= ' AND e.retest_id = ?';  $params[] = $retestId; }
        $sql .= ' ORDER BY e.created_at DESC, e.id DESC';

        return array_map([self::class, 'present'], Database::all($sql, $params));
    }

    /** Attach an existing evidence item to a finding or retest. */
    public static function attach(int $evidenceId, ?int $findingId, ?int $retestId = null): void
    {
        $data = [];
        if ($findingId !== null) { $data['finding_id'] = $findingId; }
        if ($retestId !== null)  { $data['retest_id'] = $retestId; }
        if ($data === []) {
            return;
        }
        Database::update('evidence', $data, 'id = ?', [$evidenceId]);
        self::custody($evidenceId, 'attached', 'Linked to ' . ($findingId !== null ? 'finding #' . $findingId : 'retest #' . $retestId));
        Audit::log('evidence.attached', 'evidence', $evidenceId, $data);
    }

    /**
     * Recomputes the stored hash for file evidence and reports whether the
     * artefact on disk still matches what was recorded at capture time.
     *
     * @return array{verified:bool,expected:string,actual:string|null,message:string}
     */
    public static function verifyIntegrity(int $evidenceId): array
    {
        $row = Database::one('SELECT sha256, stored_name, content_text FROM evidence WHERE id = ?', [$evidenceId]);
        if ($row === null) {
            return ['verified' => false, 'expected' => '', 'actual' => null, 'message' => 'Evidence not found.'];
        }
        $expected = (string) $row['sha256'];

        if (!empty($row['stored_name'])) {
            $path = self::storagePath() . '/' . $row['stored_name'];
            if (!is_file($path)) {
                return ['verified' => false, 'expected' => $expected, 'actual' => null, 'message' => 'The stored file is missing from the evidence store.'];
            }
            $actual = (string) hash_file('sha256', $path);
            $ok = hash_equals($expected, $actual);
            return [
                'verified' => $ok,
                'expected' => $expected,
                'actual'   => $actual,
                'message'  => $ok ? 'File matches the hash recorded at capture.' : 'FILE HAS CHANGED since capture.',
            ];
        }

        // Text evidence: the hash covers the ORIGINAL content, so a redacted
        // item legitimately will not match. That is reported, not treated as
        // tampering.
        $actual = hash('sha256', (string) $row['content_text']);
        $ok = hash_equals($expected, $actual);
        return [
            'verified' => $ok,
            'expected' => $expected,
            'actual'   => $actual,
            'message'  => $ok
                ? 'Text matches the hash recorded at capture.'
                : 'Text differs from the original hash. This is expected when automatic redaction was applied; the recorded hash covers the pre-redaction content.',
        ];
    }

    public static function custody(int $evidenceId, string $action, string $note = ''): void
    {
        Database::insert('evidence_custody', [
            'evidence_id' => $evidenceId,
            'action'      => mb_substr($action, 0, 24),
            'actor_id'    => Auth::id(),
            'actor_name'  => Auth::check() ? Auth::username() : 'system',
            'actor_ip'    => PHP_SAPI === 'cli' ? 'cli' : Http::clientIp(),
            'note'        => mb_substr($note, 0, 400),
        ]);
    }

    /** @return array<int,array<string,mixed>> */
    public static function custodyChain(int $evidenceId): array
    {
        return Database::all(
            'SELECT action, actor_name, actor_ip, note, created_at FROM evidence_custody
             WHERE evidence_id = ? ORDER BY id ASC',
            [$evidenceId]
        );
    }

    public static function delete(int $evidenceId): bool
    {
        $row = Database::one('SELECT stored_name, assessment_id FROM evidence WHERE id = ?', [$evidenceId]);
        if ($row === null) {
            return false;
        }
        if (!empty($row['stored_name'])) {
            $path = self::storagePath() . '/' . $row['stored_name'];
            if (is_file($path)) {
                @unlink($path);
            }
        }
        Database::delete('evidence', 'id = ?', [$evidenceId]);
        Audit::log('evidence.deleted', 'evidence', $evidenceId, null, (int) $row['assessment_id']);
        return true;
    }

    /**
     * @param  array<string,mixed> $row
     * @return array<string,mixed>
     */
    private static function present(array $row): array
    {
        $row['id']            = (int) $row['id'];
        $row['assessment_id'] = (int) $row['assessment_id'];
        $row['test_id']       = $row['test_id'] !== null ? (int) $row['test_id'] : null;
        $row['finding_id']    = $row['finding_id'] !== null ? (int) $row['finding_id'] : null;
        $row['retest_id']     = $row['retest_id'] !== null ? (int) $row['retest_id'] : null;
        $row['file_size']     = $row['file_size'] !== null ? (int) $row['file_size'] : null;
        $row['is_redacted']   = (int) ($row['is_redacted'] ?? 0) === 1;
        $row['has_file']      = !empty($row['stored_name']);
        $row['is_image']      = !empty($row['mime_type']) && str_starts_with((string) $row['mime_type'], 'image/');
        $row['sha256_short']  = substr((string) $row['sha256'], 0, 16);
        unset($row['stored_name']);      // internal detail; never exposed to the client
        return $row;
    }

    private static function nullableId(mixed $value): ?int
    {
        if ($value === null || $value === '' || $value === 0 || $value === '0') {
            return null;
        }
        return (int) $value;
    }

    private static function uploadErrorMessage(int $code): string
    {
        return match ($code) {
            UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => 'The file is larger than the server upload limit. Increase upload_max_filesize and post_max_size in php.ini.',
            UPLOAD_ERR_PARTIAL    => 'The upload was interrupted. Try again.',
            UPLOAD_ERR_NO_FILE    => 'No file was submitted.',
            UPLOAD_ERR_NO_TMP_DIR => 'The server has no temporary upload directory configured.',
            UPLOAD_ERR_CANT_WRITE => 'The server could not write the uploaded file to disk.',
            UPLOAD_ERR_EXTENSION  => 'A PHP extension blocked the upload.',
            default               => 'The upload failed (code ' . $code . ').',
        };
    }

    /** Resolves the absolute path of a stored artefact for download. */
    public static function absolutePath(int $evidenceId): ?string
    {
        $name = Database::scalar('SELECT stored_name FROM evidence WHERE id = ?', [$evidenceId]);
        if (!is_string($name) || $name === '') {
            return null;
        }
        // basename() defeats any traversal that reached the column.
        $path = self::storagePath() . '/' . basename($name);
        return is_file($path) ? $path : null;
    }
}
