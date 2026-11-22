<?php

declare(strict_types=1);

class RDAP
{
  public string $domain;

  public string $extension;

  /** @var array<string, string> */
  private array $servers;

  private string $server;

  private const SERVERS_IANA = __DIR__ . "/data/rdap-servers-iana.json";

  private const SERVERS_EXTRA = __DIR__ . "/data/rdap-servers-extra.json";

  /**
   * @throws JsonException
   */
  public function __construct(string $domain, string $extension, ?string $extensionTop)
  {
    $this->domain = $domain;
    $this->extension = $extension;

    $this->servers = $this->getServers();

    if (!empty($extensionTop) && !array_key_exists($extension, $this->servers)) {
      $this->extension = $extensionTop;
    }

    $server = $_GET["rdap-server"] ?? "";
    if ($server) {
      $this->server = $server;
    } else {
      $this->server = $this->getServer();
    }
  }

  /**
   * @return array<string, string>
   *
   * @throws JsonException
   */
  private function getServers(): array
  {
    $servers = [];

    foreach ([self::SERVERS_IANA, self::SERVERS_EXTRA] as $file) {
      if (($jsonText = @file_get_contents($file)) === false) {
        continue;
      }

      $json = json_decode($jsonText, true, flags: JSON_THROW_ON_ERROR);

      if ($file === self::SERVERS_IANA) {
        foreach ($json["services"] as $service) {
          $tlds = $service[0];
          $server = $service[1][0];

          foreach ($tlds as $tld) {
            $servers[$tld] = $server;
          }
        }
      } else {
        $servers = array_merge($servers, $json);
      }
    }

    return $servers;
  }

  private function getServer(): string
  {
    if ($this->extension === "iana") {
      return "https://rdap.iana.org/";
    }

    $extension = idn_to_ascii($this->extension) ?: $this->extension;
    $server = $this->servers[$extension] ?? "";

    if (empty($server)) {
      throw new RuntimeException("No RDAP server found for '$this->domain'.");
    }

    return $server;
  }

  /**
   * RDAP hosts known to sit behind a per-URL cache and to decode
   * percent-encoded names. Others get the plain name (dropcatch patch).
   * Extend with the CACHE_BUST_RDAP_HOSTS environment variable (comma list).
   */
  private const CACHE_BUST_HOSTS = ["ccrdap.twnic.tw"];

  private static function bustsCache(string $server): bool
  {
    $host = strtolower((string)parse_url($server, PHP_URL_HOST));
    $extra = array_filter(array_map("trim", explode(",", strtolower((string)getenv("CACHE_BUST_RDAP_HOSTS")))));
    return in_array($host, array_merge(self::CACHE_BUST_HOSTS, $extra), true);
  }

  /**
   * Percent-encodes one randomly chosen letter of the name (RFC 3986 allows
   * any unreserved character to be encoded; servers decode it). Each call
   * yields one of many equivalent URLs, defeating per-URL CDN caches.
   */
  public static function cacheBustPath(string $domain): string
  {
    $positions = [];
    $len = strlen($domain);
    for ($i = 0; $i < $len; $i++) {
      if (ctype_alnum($domain[$i])) {
        $positions[] = $i;
      }
    }
    if (!$positions) {
      return rawurlencode($domain);
    }
    // encode a random subset (at least one) of the alphanumeric characters
    $out = "";
    $pick = $positions[random_int(0, count($positions) - 1)];
    for ($i = 0; $i < $len; $i++) {
      $c = $domain[$i];
      if ($i === $pick || (ctype_alnum($c) && random_int(0, 3) === 0)) {
        $out .= sprintf("%%%02X", ord($c));
      } else {
        $out .= $c;
      }
    }
    return $out;
  }

  /** @return array{0:int, 1:string} */
  public function getData(): array
  {
    $server = rtrim($this->server, "/");
    $domain = idn_to_ascii($this->domain) ?: $this->domain;

    // Some registries serve RDAP through a CDN that caches per exact URL
    // (e.g. TWNIC ccrdap.twnic.tw: "x-cache: HIT" copies hours old). Query
    // strings are rejected there (404) but percent-encoding one character of
    // the name is decoded by the origin while forming a new cache key, so a
    // varying encoding forces a fresh answer (dropcatch patch).
    $path = self::bustsCache($server) ? self::cacheBustPath($domain) : $domain;
    $ch = curl_init("$server/domain/$path");

    $defaultOptions = [
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_FOLLOWLOCATION => true,
      CURLOPT_CONNECTTIMEOUT => 10,
      CURLOPT_TIMEOUT => 10,
      CURLOPT_USERAGENT => USER_AGENT,
      CURLOPT_FRESH_CONNECT => true,
      CURLOPT_FORBID_REUSE => true,
      CURLOPT_HTTPHEADER => ["Accept: application/rdap+json, application/json", "Cache-Control: no-cache", "Pragma: no-cache"],
    ];

    curl_setopt_array($ch, array_replace($defaultOptions, getServerCurlOptions($server)));

    $response = curl_exec($ch);
    if (is_bool($response)) {
      $error = curl_error($ch);
      throw new RuntimeException("RDAP lookup failed for '$this->domain': $error.");
    }

    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    if ($code >= 400 && $code !== 404 && $code !== 429) {
      throw new RuntimeException("RDAP lookup failed for '$this->domain': HTTP $code.");
    }

    $contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    if (!is_string($contentType) || !preg_match("/^application\/(rdap\+)?json/i", $contentType)) {
      $response = "";
    }

    return [$code, $response];
  }
}
