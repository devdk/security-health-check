<?php
/**
 * WP-CLI commands: wp shc pair|send|status|report|disconnect.
 *
 * @package shc-companion
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manage the Security Health Check companion.
 */
class SHC_Companion_CLI {

	/**
	 * Connects this site using a pairing code from the dashboard and sends the first report.
	 *
	 * ## OPTIONS
	 *
	 * <code>
	 * : The one-time pairing code, for example ABCDE-FGHJK.
	 *
	 * [--service=<url>]
	 * : Service address. Defaults to the saved address or SHC_COMPANION_SERVICE.
	 */
	public function pair( $args, $assoc_args ) {
		$service = isset( $assoc_args['service'] ) ? $assoc_args['service'] : SHC_Companion_Client::service();
		$result  = SHC_Companion_Client::pair( $args[0], $service );
		$this->finish( $result );
	}

	/**
	 * Sends a signed report now.
	 */
	public function send() {
		$this->finish( SHC_Companion_Client::send_report() );
	}

	/**
	 * Shows the connection state.
	 */
	public function status() {
		$connection = SHC_Companion_Client::connection();
		if ( ! $connection ) {
			WP_CLI::line( 'Not connected.' );
			return;
		}
		WP_CLI::line( 'Connected to ' . $connection['service'] );
		WP_CLI::line( 'Connected since: ' . $connection['connectedAt'] );
		WP_CLI::line( 'Key expires: ' . $connection['expiresAt'] );
		$last = SHC_Companion_Client::last_result();
		WP_CLI::line( $last ? 'Last report: ' . $last['time'] . ' ' . ( $last['ok'] ? 'sent' : 'failed' ) . '. ' . $last['message'] : 'Last report: none yet' );
	}

	/**
	 * Prints the report as JSON without sending it.
	 */
	public function report() {
		$collector = new SHC_Companion_Collector();
		WP_CLI::line( SHC_Companion_Collector::to_json( $collector->collect( SHC_COMPANION_VERSION ), true ) );
	}

	/**
	 * Forgets the key on this site. Revoke it on the dashboard too if you want the service to stop accepting it.
	 */
	public function disconnect() {
		SHC_Companion_Client::disconnect();
		WP_CLI::success( 'Disconnected on this site.' );
	}

	private function finish( $result ) {
		if ( $result['ok'] ) {
			WP_CLI::success( $result['message'] );
		} else {
			WP_CLI::error( $result['message'] );
		}
	}
}
