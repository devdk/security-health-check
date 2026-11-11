<?php
/**
 * Pairing and signed report delivery. Every method returns a result array and never throws:
 * array( 'ok' => bool, 'code' => string, 'message' => string ).
 *
 * @package shc-companion
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SHC_Companion_Client {

	const OPTION_SERVICE    = 'shc_companion_service';
	const OPTION_CONNECTION = 'shc_companion_connection';
	const OPTION_LAST       = 'shc_companion_last';
	const CRON_HOOK         = 'shc_companion_daily_report';

	/** The configured service address: the constant wins and locks the field. */
	public static function service() {
		if ( self::service_locked() ) {
			return (string) SHC_COMPANION_SERVICE;
		}
		return (string) get_option( self::OPTION_SERVICE, '' );
	}

	public static function service_locked() {
		return defined( 'SHC_COMPANION_SERVICE' ) && '' !== (string) SHC_COMPANION_SERVICE;
	}

	/** The address without a trailing slash, or null when it is not usable. */
	public static function normalize_service( $input ) {
		$url = esc_url_raw( trim( (string) $input ), array( 'http', 'https' ) );
		$parts = wp_parse_url( $url );
		if ( empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
			return null;
		}
		if ( 'https' !== $parts['scheme'] && ! ( defined( 'SHC_COMPANION_ALLOW_HTTP' ) && SHC_COMPANION_ALLOW_HTTP ) ) {
			return null;
		}
		$port = isset( $parts['port'] ) ? ':' . (int) $parts['port'] : '';
		$path = isset( $parts['path'] ) ? rtrim( $parts['path'], '/' ) : '';
		return $parts['scheme'] . '://' . $parts['host'] . $port . $path;
	}

	/** The stored connection (keyId, key, expiresAt, connectedAt, service) or null. */
	public static function connection() {
		$connection = get_option( self::OPTION_CONNECTION );
		if ( is_array( $connection ) && ! empty( $connection['keyId'] ) && ! empty( $connection['key'] ) ) {
			return $connection;
		}
		return null;
	}

	public static function last_result() {
		$last = get_option( self::OPTION_LAST );
		return is_array( $last ) ? $last : null;
	}

	/** Local only: the service keeps the key until it expires or the owner revokes it on the dashboard. */
	public static function disconnect() {
		delete_option( self::OPTION_CONNECTION );
		delete_option( self::OPTION_LAST );
	}

	public static function pair( $code, $service_input ) {
		$service = self::normalize_service( $service_input );
		if ( null === $service ) {
			return self::fail( 'bad_service', 'The service address must be a full https:// address.' );
		}
		$code = sanitize_text_field( $code );
		if ( '' === $code || strlen( $code ) > 32 ) {
			return self::fail( 'bad_code', 'Enter the pairing code shown on the site page of the dashboard.' );
		}

		$body     = wp_json_encode(
			array(
				'code'          => $code,
				'homeUrl'       => home_url(),
				'pluginVersion' => SHC_COMPANION_VERSION,
			),
			JSON_UNESCAPED_SLASHES
		);
		$response = self::post( $service . SHC_Companion_Protocol::PAIR_PATH, $body, array() );
		if ( ! $response['ok'] ) {
			return $response;
		}
		$data = $response['data'];
		if (
			201 !== $response['status'] ||
			! is_array( $data ) ||
			empty( $data['keyId'] ) || ! is_string( $data['keyId'] ) ||
			empty( $data['key'] ) || ! is_string( $data['key'] ) ||
			1 !== preg_match( '/\A[A-Za-z0-9_-]{16,128}\z/', $data['key'] ) ||
			1 !== preg_match( '/\A[0-9a-f-]{36}\z/', $data['keyId'] )
		) {
			return self::fail( 'bad_response', 'The service answered, but not with a key. Check the service address.' );
		}

		update_option(
			self::OPTION_CONNECTION,
			array(
				'service'     => $service,
				'keyId'       => $data['keyId'],
				'key'         => $data['key'],
				'expiresAt'   => isset( $data['expiresAt'] ) ? sanitize_text_field( (string) $data['expiresAt'] ) : '',
				'connectedAt' => gmdate( 'c' ),
			),
			false
		);
		if ( ! self::service_locked() ) {
			update_option( self::OPTION_SERVICE, $service, false );
		}

		$first = self::send_report();
		$tail  = $first['ok'] ? 'The first report was sent.' : 'The first report could not be sent: ' . $first['message'];
		return array(
			'ok'      => true,
			'code'    => 'paired',
			'message' => 'Connected. ' . $tail,
		);
	}

	public static function send_report() {
		$connection = self::connection();
		if ( null === $connection ) {
			return self::fail( 'not_connected', 'This site is not connected yet.' );
		}

		$collector = new SHC_Companion_Collector();
		$json      = SHC_Companion_Collector::to_json( $collector->collect( SHC_COMPANION_VERSION ) );
		if ( ! is_string( $json ) ) {
			return self::record( self::fail( 'encode_failed', 'The report could not be encoded.' ) );
		}

		$timestamp = time();
		$nonce     = SHC_Companion_Protocol::nonce();
		$headers   = array(
			'X-SHC-Key-Id'    => $connection['keyId'],
			'X-SHC-Timestamp' => (string) $timestamp,
			'X-SHC-Nonce'     => $nonce,
			'X-SHC-Signature' => SHC_Companion_Protocol::signature( $connection['key'], 'POST', SHC_Companion_Protocol::REPORTS_PATH, $timestamp, $nonce, $json ),
		);

		$service  = isset( $connection['service'] ) ? $connection['service'] : self::service();
		$response = self::post( $service . SHC_Companion_Protocol::REPORTS_PATH, $json, $headers );
		if ( $response['ok'] && 202 !== $response['status'] ) {
			$response = self::fail( 'bad_response', 'Unexpected answer from the service (HTTP ' . $response['status'] . ').' );
		}
		if ( $response['ok'] ) {
			$response['message'] = 'Report sent.';
		}
		return self::record( $response );
	}

	private static function record( $result ) {
		update_option(
			self::OPTION_LAST,
			array(
				'time'    => gmdate( 'c' ),
				'ok'      => $result['ok'],
				'message' => $result['message'],
			),
			false
		);
		return $result;
	}

	private static function fail( $code, $message ) {
		return array(
			'ok'      => false,
			'code'    => $code,
			'message' => $message,
			'status'  => 0,
			'data'    => null,
		);
	}

	/** POST JSON. ok is true for any 2xx answer; other answers come back as failures carrying the API's message. */
	private static function post( $url, $body, $headers ) {
		// The safe variant refuses private and loopback addresses; development setups opt out explicitly.
		$send     = defined( 'SHC_COMPANION_ALLOW_HTTP' ) && SHC_COMPANION_ALLOW_HTTP ? 'wp_remote_post' : 'wp_safe_remote_post';
		$response = $send(
			$url,
			array(
				'timeout'     => 30,
				'redirection' => 0,
				'headers'     => array_merge( array( 'Content-Type' => 'application/json' ), $headers ),
				'body'        => $body,
			)
		);
		if ( is_wp_error( $response ) ) {
			return self::fail( 'request_failed', 'Could not reach the service: ' . sanitize_text_field( $response->get_error_message() ) );
		}

		$status = (int) wp_remote_retrieve_response_code( $response );
		$data   = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( $status >= 200 && $status < 300 ) {
			return array(
				'ok'      => true,
				'code'    => 'ok',
				'message' => '',
				'status'  => $status,
				'data'    => $data,
			);
		}

		$code    = is_array( $data ) && isset( $data['error'] ) && is_string( $data['error'] ) ? sanitize_key( $data['error'] ) : 'http_' . $status;
		$message = is_array( $data ) && isset( $data['message'] ) && is_string( $data['message'] ) ? $data['message'] : '';
		$message = SHC_Companion_Protocol::clean_text( sanitize_text_field( $message ), 300 );
		if ( '' === $message ) {
			$message = $status >= 300 && $status < 400 ? 'The service address redirected somewhere else. Check the address.' : 'The service answered with HTTP ' . $status . '.';
		}
		$result           = self::fail( $code, $message );
		$result['status'] = $status;
		return $result;
	}
}
