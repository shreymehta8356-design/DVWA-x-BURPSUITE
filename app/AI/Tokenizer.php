<?php

declare(strict_types=1);

namespace App\AI;

/**
 * Text normalisation shared by every offline model in the platform.
 *
 * Security observations are short and jargon-heavy, so the tokeniser keeps a
 * small security lexicon intact (payload markers, header names, SQL keywords),
 * strips English stop words, applies a light suffix stemmer and emits bigrams.
 * Bigrams matter here: "single quote", "session cookie" and "stack trace"
 * carry far more signal than the words alone.
 */
final class Tokenizer
{
    private const STOPWORDS = [
        'a','an','the','and','or','but','if','then','than','that','this','these','those','is','are','was','were',
        'be','been','being','to','of','in','on','at','by','for','with','from','as','it','its','into','over',
        'we','i','you','he','she','they','them','his','her','their','our','my','me','us',
        'do','does','did','done','can','could','should','would','may','might','will','shall','have','has','had',
        'not','no','nor','so','such','only','own','same','too','very','just','also','there','here','when','where',
        'which','who','whom','what','how','why','all','any','both','each','few','more','most','other','some',
        'up','down','out','off','again','further','once','because','while','during','before','after','above','below',
        // Two-character words, listed explicitly now that tokens of length 2 are kept.
        'of','to','in','on','at','by','is','as','it','be','an','or','if','no','so','do','we','my','me','us','he','am',
    ];

    /** Terms that must survive stemming and stop-word removal unchanged. */
    private const SECURITY_LEXICON = [
        'id','os','db','xss','sqli','sql','csrf','ssrf','idor','lfi','rfi','rce','xxe','csp','tls','ssl','jwt','api','url','uri',
        'php','js','dom','http','https','html','json','xml','md5','sha1','sha256','bcrypt','aes','rsa',
        'get','post','put','head','trace','options','delete','patch',
        'cookie','httponly','samesite','secure','session','phpsessid','token','header','payload','param','parameter',
        'union','select','insert','update','drop','where','order','sleep','benchmark','waitfor','concat',
        'alert','onerror','onload','script','iframe','svg','img','eval','innerhtml',
        'passwd','etc','win','ini','traversal','wrapper','filter','base64',
        'admin','root','shell','whoami','cat','ping','curl','wget','bash','cmd',
    ];

    /**
     * @return array<int,string> unigrams followed by bigrams
     */
    public static function tokenize(string $text, bool $withBigrams = true): array
    {
        $text = mb_strtolower($text, 'UTF-8');

        // Normalise the shapes that carry meaning but would otherwise shatter.
        $text = preg_replace('~https?://\S+~', ' urltoken ', $text) ?? $text;
        $text = preg_replace('~\b\d{1,3}(?:\.\d{1,3}){3}\b~', ' iptoken ', $text) ?? $text;
        $text = preg_replace('~[\'"`]~', ' quotechar ', $text) ?? $text;
        $text = preg_replace('~<[a-z][a-z0-9]*~', ' tagtoken ', $text) ?? $text;
        $text = preg_replace('~\.\./|\.\.\\\\~', ' traversalseq ', $text) ?? $text;
        $text = preg_replace('~\bor\s+1\s*=\s*1\b~', ' tautology ', $text) ?? $text;
        $text = preg_replace('~[^a-z0-9_\-\s]~', ' ', $text) ?? $text;
        // Hyphens are inconsistent in security writing ("cross-site" and
        // "cross site" mean the same thing), so they become word boundaries
        // and the bigram pass puts the compound back together.
        $text = str_replace('-', ' ', $text);

        $raw = preg_split('/\s+/', trim($text)) ?: [];

        $unigrams = [];
        foreach ($raw as $word) {
            if ($word === '') {
                continue;
            }
            if (in_array($word, self::SECURITY_LEXICON, true)) {
                $unigrams[] = $word;
                continue;
            }
            // Two-character tokens are kept: "id" is the canonical injection
            // parameter name in this domain, and dropping it silently removed
            // the strongest signal from a whole class of observations.
            if (mb_strlen($word) < 2 || in_array($word, self::STOPWORDS, true)) {
                continue;
            }
            if (mb_strlen($word) > 40) {
                $word = mb_substr($word, 0, 40);
            }
            $unigrams[] = self::stem($word);
        }

        if (!$withBigrams || count($unigrams) < 2) {
            return $unigrams;
        }

        $tokens = $unigrams;
        $count = count($unigrams);
        for ($i = 0; $i < $count - 1; $i++) {
            $tokens[] = $unigrams[$i] . '_' . $unigrams[$i + 1];
        }
        return $tokens;
    }

    /**
     * Light Porter-style suffix stripping. Deliberately conservative: over
     * stemming destroys short security terms.
     */
    public static function stem(string $word): string
    {
        if (mb_strlen($word) <= 4) {
            return $word;
        }
        // Words that are not plurals despite the trailing s ("cross", "access",
        // "status", "bypass"). Stripping it here produced "cros" and "acces",
        // which silently split features that should have matched.
        if (preg_match('/(ss|us|is|as)$/', $word)) {
            return $word;
        }

        static $suffixes = ['ational' => 'ate', 'tional' => 'tion', 'ization' => 'ize', 'iveness' => 'ive',
                            'fulness' => 'ful', 'ousness' => 'ous', 'ities' => 'ity', 'ement' => '',
                            'ments' => '', 'ment' => '', 'ing' => '', 'edly' => '', 'ely' => '',
                            'ies' => 'y', 'ied' => 'y', 'ers' => 'er', 'ed' => '', 'es' => '', 'ly' => '', 's' => ''];

        foreach ($suffixes as $suffix => $replacement) {
            $len = strlen($suffix);
            if (strlen($word) > $len + 3 && str_ends_with($word, $suffix)) {
                $stemmed = substr($word, 0, -$len) . $replacement;
                return strlen($stemmed) >= 3 ? $stemmed : $word;
            }
        }
        return $word;
    }

    /**
     * Term frequency map.
     *
     * @return array<string,int>
     */
    public static function counts(string $text, bool $withBigrams = true): array
    {
        $counts = [];
        foreach (self::tokenize($text, $withBigrams) as $token) {
            $counts[$token] = ($counts[$token] ?? 0) + 1;
        }
        return $counts;
    }
}
