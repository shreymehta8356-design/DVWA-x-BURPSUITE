<?php

declare(strict_types=1);

namespace App\AI;

/**
 * TF-IDF vector space model with cosine similarity - pure PHP, offline.
 *
 * Two jobs in this platform:
 *   1. Duplicate detection. Long assessments accumulate near-identical
 *      findings ("Reflected XSS in name parameter" vs "XSS via name field").
 *      Before a new finding is saved the platform scores it against every
 *      existing finding in the assessment and warns above the configured
 *      threshold, so the report does not double count the same issue.
 *   2. Nearest-check retrieval. A free-text observation is matched against the
 *      security check catalogue to suggest which predefined check it belongs to.
 *
 *   tf   = 1 + log(raw count)                 (sublinear scaling)
 *   idf  = log((N + 1) / (df + 1)) + 1        (smoothed)
 *   sim  = cosine of the L2-normalised tf-idf vectors
 */
final class TfIdfIndex
{
    /** @var array<int|string,array<string,float>> id => term => tf */
    private array $documents = [];
    /** @var array<string,int> term => document frequency */
    private array $df = [];
    /** @var array<int|string,array<string,float>> id => normalised tf-idf vector */
    private array $vectors = [];
    /** @var array<int|string,mixed> id => caller supplied payload */
    private array $meta = [];
    private bool $built = false;

    public function add(int|string $id, string $text, mixed $meta = null): void
    {
        $counts = Tokenizer::counts($text);
        if ($counts === []) {
            return;
        }
        $tf = [];
        foreach ($counts as $term => $n) {
            $tf[$term] = 1.0 + log((float) $n);
        }
        $this->documents[$id] = $tf;
        $this->meta[$id] = $meta;
        foreach (array_keys($tf) as $term) {
            $this->df[$term] = ($this->df[$term] ?? 0) + 1;
        }
        $this->built = false;
    }

    public function build(): void
    {
        $n = count($this->documents);
        $this->vectors = [];
        if ($n === 0) {
            $this->built = true;
            return;
        }
        foreach ($this->documents as $id => $tf) {
            $vector = [];
            $norm = 0.0;
            foreach ($tf as $term => $weight) {
                $idf = log(($n + 1) / (($this->df[$term] ?? 0) + 1)) + 1.0;
                $value = $weight * $idf;
                $vector[$term] = $value;
                $norm += $value * $value;
            }
            $norm = sqrt($norm);
            if ($norm > 0.0) {
                foreach ($vector as $term => $value) {
                    $vector[$term] = $value / $norm;
                }
            }
            $this->vectors[$id] = $vector;
        }
        $this->built = true;
    }

    /** @return array<string,float> normalised tf-idf vector for unseen text */
    public function vectorise(string $text): array
    {
        if (!$this->built) {
            $this->build();
        }
        $n = max(1, count($this->documents));
        $counts = Tokenizer::counts($text);
        $vector = [];
        $norm = 0.0;
        foreach ($counts as $term => $count) {
            $idf = log(($n + 1) / (($this->df[$term] ?? 0) + 1)) + 1.0;
            $value = (1.0 + log((float) $count)) * $idf;
            $vector[$term] = $value;
            $norm += $value * $value;
        }
        $norm = sqrt($norm);
        if ($norm > 0.0) {
            foreach ($vector as $term => $value) {
                $vector[$term] = $value / $norm;
            }
        }
        return $vector;
    }

    /**
     * @param array<string,float> $a
     * @param array<string,float> $b
     */
    public static function cosine(array $a, array $b): float
    {
        // Both vectors are already L2-normalised, so the dot product is cosine.
        if (count($a) > count($b)) {
            [$a, $b] = [$b, $a];
        }
        $dot = 0.0;
        foreach ($a as $term => $value) {
            if (isset($b[$term])) {
                $dot += $value * $b[$term];
            }
        }
        return max(0.0, min(1.0, $dot));
    }

    /**
     * @return array<int,array{id:int|string,score:float,meta:mixed,shared_terms:array<int,string>}>
     */
    public function similar(string $text, int $topN = 5, float $minScore = 0.0): array
    {
        if (!$this->built) {
            $this->build();
        }
        $query = $this->vectorise($text);
        if ($query === []) {
            return [];
        }

        $results = [];
        foreach ($this->vectors as $id => $vector) {
            $score = self::cosine($query, $vector);
            if ($score < $minScore) {
                continue;
            }
            $shared = [];
            foreach ($query as $term => $weight) {
                if (isset($vector[$term])) {
                    $shared[str_replace('_', ' ', $term)] = $weight * $vector[$term];
                }
            }
            arsort($shared);
            $results[] = [
                'id'           => $id,
                'score'        => round($score, 4),
                'meta'         => $this->meta[$id] ?? null,
                'shared_terms' => array_slice(array_keys($shared), 0, 5),
            ];
        }

        usort($results, static fn ($a, $b) => $b['score'] <=> $a['score']);
        return array_slice($results, 0, max(1, $topN));
    }

    public function size(): int
    {
        return count($this->documents);
    }
}
