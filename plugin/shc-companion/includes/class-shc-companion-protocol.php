<?php
/**
 * Signing and data rules shared with the service. No WordPress calls: the PHP tests load this file alone.
 *
 * @package shc-companion
 */

if ( ! defined( 'ABSPATH' ) && ! defined( 'SHC_COMPANION_TESTS' ) ) {
	exit;
}

class SHC_Companion_Protocol {

	const SCHEME       = 'SHC-HMAC-SHA256-V1';
	const REPORTS_PATH = '/api/plugin/reports';
	const PAIR_PATH    = '/api/plugin/pair';

	/** Within this many seconds a package marker change counts as an update of the whole package. */
	const UPDATE_WINDOW_SECONDS = 3600;

	/** An index.php longer than this is never read. */
	const SILENT_INDEX_MAX_BYTES = 200;

	public static function body_sha256( $body ) {
		return hash( 'sha256', $body );
	}

	public static function string_to_sign( $method, $path, $timestamp, $nonce, $body ) {
		return implode(
			"\n",
			array( self::SCHEME, strtoupper( $method ), $path, (string) $timestamp, $nonce, self::body_sha256( $body ) )
		);
	}

	/** Header value: "v1=" and the hex HMAC-SHA256 of the string to sign, keyed with the key's text. */
	public static function signature( $key, $method, $path, $timestamp, $nonce, $body ) {
		return 'v1=' . hash_hmac( 'sha256', self::string_to_sign( $method, $path, $timestamp, $nonce, $body ), $key );
	}

	/** 32 characters of [A-Za-z0-9_-], new for every request. */
	public static function nonce() {
		return rtrim( strtr( base64_encode( random_bytes( 24 ) ), '+/', '-_' ), '=' );
	}

	/** Same rule as mask() in packages/shared: first and last character, up to six stars between. */
	public static function mask( $value ) {
		$chars = preg_split( '//u', $value, -1, PREG_SPLIT_NO_EMPTY );
		if ( false === $chars ) {
			$chars = str_split( $value );
		}
		$count = count( $chars );
		if ( $count <= 2 ) {
			return str_repeat( '*', $count );
		}
		return $chars[0] . str_repeat( '*', min( $count - 2, 6 ) ) . $chars[ $count - 1 ];
	}

	/** True for an index.php that only says <?php, optionally "// Silence is golden." and optionally ?>. */
	public static function is_silent_index( $content ) {
		if ( strlen( $content ) > self::SILENT_INDEX_MAX_BYTES ) {
			return false;
		}
		return 1 === preg_match( '/\A<\?php\s*(?:\/\/\s*Silence is golden\.?\s*)?(?:\?>\s*)?\z/', $content );
	}

	public static function is_php_extension( $file_name ) {
		return 1 === preg_match( '/\.(?:php[3-8]?|phtml|phar|pht)\z/i', $file_name );
	}

	/** True when the package's marker file changed close to the file: that is what an update looks like. */
	public static function package_updated( $marker_mtime, $file_mtime ) {
		if ( null === $marker_mtime ) {
			return false;
		}
		return abs( $marker_mtime - $file_mtime ) <= self::UPDATE_WINDOW_SECONDS;
	}

	/** For "plugins/<slug>/file.php" or "themes/<slug>/file.php" returns array( type, slug ); null otherwise. */
	public static function package_of( $path_in_content ) {
		if ( 1 === preg_match( '#\A(plugins|themes)/([^/]+)/.+#', $path_in_content, $m ) ) {
			return array( $m[1], $m[2] );
		}
		return null;
	}

	/** A version string the service accepts, or null. */
	public static function clean_version( $value ) {
		$value = preg_replace( '/[^0-9A-Za-z.+_-]/', '', (string) $value );
		$value = substr( $value, 0, 64 );
		return '' === $value ? null : $value;
	}

	/** Text without control characters, valid UTF-8, at most $max characters. */
	public static function clean_text( $value, $max ) {
		$value = (string) $value;
		if ( 1 !== preg_match( '//u', $value ) ) {
			$value = preg_replace( '/[^\x20-\x7E]/', '?', $value );
		}
		$value = preg_replace( '/[\x00-\x1f]/', ' ', $value );
		if ( 1 === preg_match( '/\A.{0,' . (int) $max . '}/su', $value, $m ) ) {
			return $m[0];
		}
		return '';
	}

	/** A relative path the service accepts: no control characters, no leading slash, at most 500 characters. */
	public static function clean_path( $path ) {
		$path = self::clean_text( str_replace( '\\', '/', $path ), 500 );
		return ltrim( $path, '/' );
	}

	public static function iso_time( $timestamp ) {
		return gmdate( 'Y-m-d\TH:i:s\Z', $timestamp );
	}
}
