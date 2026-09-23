<?php

declare(strict_types=1);

namespace App\Core;

/**
 * Minimal method + path router with {placeholder} segments.
 * Routes are declared in api/routes.php.
 */
final class Router
{
    /** @var array<int,array{method:string,pattern:string,regex:string,keys:array<int,string>,handler:callable|array,options:array}> */
    private array $routes = [];

    public function add(string $method, string $pattern, callable|array $handler, array $options = []): void
    {
        $keys = [];
        $regex = preg_replace_callback(
            '/\{([a-zA-Z_][a-zA-Z0-9_]*)\}/',
            static function (array $m) use (&$keys): string {
                $keys[] = $m[1];
                return '([^/]+)';
            },
            $pattern
        ) ?? $pattern;

        $this->routes[] = [
            'method'  => strtoupper($method),
            'pattern' => $pattern,
            'regex'   => '#^' . $regex . '$#',
            'keys'    => $keys,
            'handler' => $handler,
            'options' => $options,
        ];
    }

    public function get(string $p, callable|array $h, array $o = []): void    { $this->add('GET', $p, $h, $o); }
    public function post(string $p, callable|array $h, array $o = []): void   { $this->add('POST', $p, $h, $o); }
    public function put(string $p, callable|array $h, array $o = []): void    { $this->add('PUT', $p, $h, $o); }
    public function patch(string $p, callable|array $h, array $o = []): void  { $this->add('PATCH', $p, $h, $o); }
    public function delete(string $p, callable|array $h, array $o = []): void { $this->add('DELETE', $p, $h, $o); }

    /**
     * Dispatch. Returns the handler result; never returns when the handler
     * emits a response through Http::json().
     */
    public function dispatch(string $method, string $path): mixed
    {
        $method = strtoupper($method);
        $pathMatched = false;

        foreach ($this->routes as $route) {
            if (!preg_match($route['regex'], $path, $matches)) {
                continue;
            }
            $pathMatched = true;
            if ($route['method'] !== $method) {
                continue;
            }

            array_shift($matches);
            $params = [];
            foreach ($route['keys'] as $i => $key) {
                $params[$key] = $matches[$i] ?? null;
            }

            // Guards -------------------------------------------------------
            $options = $route['options'];
            if (($options['auth'] ?? true) === true) {
                Auth::requireLogin();
            }
            if (!empty($options['roles'])) {
                Auth::requireRole((array) $options['roles']);
            }
            if (in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true) && ($options['csrf'] ?? true) === true) {
                Csrf::requireValidToken();
            }

            $handler = $route['handler'];
            if (is_array($handler)) {
                [$class, $action] = $handler;
                $instance = new $class();
                return $instance->{$action}($params);
            }
            return $handler($params);
        }

        if ($pathMatched) {
            Http::fail('Method not allowed for this endpoint.', 405);
        }
        Http::fail('Endpoint not found: ' . $path, 404);
    }
}
