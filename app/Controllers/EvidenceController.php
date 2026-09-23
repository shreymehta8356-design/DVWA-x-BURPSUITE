<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Core\Auth;
use App\Core\Database;
use App\Core\Http;
use App\Services\EvidenceService;

final class EvidenceController
{
    public function index(array $params): never
    {
        Auth::must('assessment.view');
        $testId    = Http::int('test_id', 0);
        $findingId = Http::int('finding_id', 0);
        Http::ok(EvidenceService::listFor(
            (int) $params['id'],
            $testId > 0 ? $testId : null,
            $findingId > 0 ? $findingId : null
        ));
    }

    public function show(array $params): never
    {
        Auth::must('assessment.view');
        $id = (int) $params['evidenceId'];
        $evidence = EvidenceService::find($id);
        if ($evidence === null) {
            Http::fail('Evidence not found.', 404);
        }
        EvidenceService::custody($id, 'viewed');
        $evidence['custody'] = EvidenceService::custodyChain($id);
        Http::ok($evidence);
    }

    public function storeText(array $params): never
    {
        Auth::must('evidence.add');
        Http::ok(
            EvidenceService::captureText((int) $params['id'], Http::body()),
            ['message' => 'Evidence recorded and hashed.']
        );
    }

    public function upload(array $params): never
    {
        Auth::must('evidence.add');
        if (empty($_FILES['file'])) {
            Http::fail('No file was received. Attach a file with the field name "file".', 422);
        }
        // Multipart bodies carry the CSRF token and metadata as form fields.
        Http::ok(
            EvidenceService::captureFile((int) $params['id'], $_FILES['file'], $_POST),
            ['message' => 'Evidence stored and hashed.']
        );
    }

    /**
     * Streams a stored artefact. Served with a restrictive content type and a
     * download disposition so a stored HTML or SVG artefact can never execute
     * in the platform origin.
     */
    public function download(array $params): never
    {
        Auth::must('assessment.view');
        $id = (int) $params['evidenceId'];
        $row = Database::one('SELECT original_name, mime_type, file_size FROM evidence WHERE id = ?', [$id]);
        $path = EvidenceService::absolutePath($id);
        if ($row === null || $path === null) {
            Http::fail('That evidence item has no stored file.', 404);
        }

        EvidenceService::custody($id, 'exported', 'File retrieved from the evidence store.');

        $mime = (string) ($row['mime_type'] ?? 'application/octet-stream');
        $inline = str_starts_with($mime, 'image/');      // images preview safely
        $filename = preg_replace('/[^A-Za-z0-9._-]/', '_', (string) ($row['original_name'] ?? 'evidence')) ?? 'evidence';

        header('Content-Type: ' . ($inline ? $mime : 'application/octet-stream'));
        header('Content-Length: ' . (string) filesize($path));
        header('Content-Disposition: ' . ($inline ? 'inline' : 'attachment') . '; filename="' . $filename . '"');
        header('X-Content-Type-Options: nosniff');
        header("Content-Security-Policy: default-src 'none'; img-src 'self'; sandbox");
        header('Cache-Control: private, no-store');
        readfile($path);
        exit;
    }

    public function verify(array $params): never
    {
        Auth::must('assessment.view');
        Http::ok(EvidenceService::verifyIntegrity((int) $params['evidenceId']));
    }

    public function attach(array $params): never
    {
        Auth::must('evidence.add');
        $findingId = Http::int('finding_id', 0);
        $retestId  = Http::int('retest_id', 0);
        if ($findingId === 0 && $retestId === 0) {
            Http::fail('Supply a finding_id or a retest_id to attach this evidence to.', 422);
        }
        EvidenceService::attach(
            (int) $params['evidenceId'],
            $findingId > 0 ? $findingId : null,
            $retestId > 0 ? $retestId : null
        );
        Http::ok(EvidenceService::find((int) $params['evidenceId']), ['message' => 'Evidence attached.']);
    }

    public function destroy(array $params): never
    {
        Auth::must('evidence.delete');
        if (!EvidenceService::delete((int) $params['evidenceId'])) {
            Http::fail('Evidence not found.', 404);
        }
        Http::ok(['deleted' => true], ['message' => 'Evidence deleted. The deletion is recorded in the audit trail.']);
    }
}
