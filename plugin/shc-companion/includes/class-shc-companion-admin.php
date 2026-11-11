<?php
/**
 * The Tools > Security Health Check page.
 *
 * @package shc-companion
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SHC_Companion_Admin {

	const PAGE = 'shc-companion';

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_post_shc_companion_pair', array( __CLASS__, 'handle_pair' ) );
		add_action( 'admin_post_shc_companion_send', array( __CLASS__, 'handle_send' ) );
		add_action( 'admin_post_shc_companion_disconnect', array( __CLASS__, 'handle_disconnect' ) );
	}

	/** On a network the report covers every site's files, so only network admins may see or change it. */
	public static function capability() {
		return is_multisite() ? 'manage_network_options' : 'manage_options';
	}

	public static function menu() {
		add_management_page( 'Security Health Check', 'Security Health Check', self::capability(), self::PAGE, array( __CLASS__, 'render' ) );
	}

	private static function guard( $action ) {
		if ( ! current_user_can( self::capability() ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'shc-companion' ), 403 );
		}
		check_admin_referer( $action );
	}

	private static function back( $result ) {
		set_transient( 'shc_companion_notice_' . get_current_user_id(), $result, 60 );
		wp_safe_redirect( admin_url( 'tools.php?page=' . self::PAGE ) );
		exit;
	}

	public static function handle_pair() {
		self::guard( 'shc_companion_pair' );
		$code    = isset( $_POST['shc_code'] ) ? sanitize_text_field( wp_unslash( $_POST['shc_code'] ) ) : '';
		$service = SHC_Companion_Client::service_locked()
			? SHC_Companion_Client::service()
			: ( isset( $_POST['shc_service'] ) ? sanitize_text_field( wp_unslash( $_POST['shc_service'] ) ) : '' );
		self::back( SHC_Companion_Client::pair( $code, $service ) );
	}

	public static function handle_send() {
		self::guard( 'shc_companion_send' );
		self::back( SHC_Companion_Client::send_report() );
	}

	public static function handle_disconnect() {
		self::guard( 'shc_companion_disconnect' );
		SHC_Companion_Client::disconnect();
		self::back(
			array(
				'ok'      => true,
				'message' => 'Disconnected on this site. To revoke the key on the service, use the dashboard.',
			)
		);
	}

	private static function post_form( $action, $label, $class = 'button' ) {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline">';
		echo '<input type="hidden" name="action" value="' . esc_attr( $action ) . '" />';
		wp_nonce_field( $action );
		echo '<button type="submit" class="' . esc_attr( $class ) . '">' . esc_html( $label ) . '</button></form> ';
	}

	public static function render() {
		if ( ! current_user_can( self::capability() ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'shc-companion' ), 403 );
		}
		$notice_key = 'shc_companion_notice_' . get_current_user_id();
		$notice     = get_transient( $notice_key );
		delete_transient( $notice_key );
		$connection = SHC_Companion_Client::connection();
		$last       = SHC_Companion_Client::last_result();
		$view       = isset( $_GET['view'] ) && 'payload' === $_GET['view']; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only display switch.

		echo '<div class="wrap"><h1>Security Health Check</h1>';
		if ( is_array( $notice ) && isset( $notice['message'] ) ) {
			printf(
				'<div class="notice %s"><p>%s</p></div>',
				esc_attr( ! empty( $notice['ok'] ) ? 'notice-success' : 'notice-error' ),
				esc_html( $notice['message'] )
			);
		}

		if ( $connection ) {
			self::render_status( $connection, $last );
		} else {
			self::render_pairing();
		}

		echo '<h2>What is sent</h2><p>The report lists plugins, themes, administrator accounts (names masked), debug settings, the permission bits of <code>wp-config.php</code>, changed core files and PHP files in the uploads folder. It never contains file contents, passwords or keys.</p>';
		if ( $view ) {
			$collector = new SHC_Companion_Collector();
			echo '<pre style="max-height:480px;overflow:auto;background:#fff;border:1px solid #c3c4c7;padding:12px">' . esc_html( SHC_Companion_Collector::to_json( $collector->collect( SHC_COMPANION_VERSION ), true ) ) . '</pre>';
			echo '<p><a href="' . esc_url( admin_url( 'tools.php?page=' . self::PAGE ) ) . '">Hide</a></p>';
		} else {
			echo '<p><a class="button" href="' . esc_url( admin_url( 'tools.php?page=' . self::PAGE . '&view=payload' ) ) . '">See exactly what is sent</a></p>';
		}
		echo '</div>';
	}

	private static function render_pairing() {
		$locked  = SHC_Companion_Client::service_locked();
		$service = SHC_Companion_Client::service();
		echo '<h2>Connect this site</h2>';
		echo '<p>Open the site page in your Security Health Check dashboard, choose <strong>Connect the plugin</strong>, and enter the service address and one-time code here.</p>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="shc_companion_pair" />';
		wp_nonce_field( 'shc_companion_pair' );
		echo '<table class="form-table" role="presentation"><tr><th scope="row"><label for="shc_service">Service address</label></th><td>';
		printf(
			'<input type="url" class="regular-text" id="shc_service" name="shc_service" value="%s" placeholder="https://" %s />',
			esc_attr( $service ),
			$locked ? 'readonly' : ''
		);
		echo '</td></tr><tr><th scope="row"><label for="shc_code">Pairing code</label></th><td><input type="text" class="regular-text" id="shc_code" name="shc_code" placeholder="ABCDE-FGHJK" autocomplete="off" required /></td></tr></table>';
		echo '<p><button type="submit" class="button button-primary">Connect</button></p></form>';
	}

	private static function render_status( $connection, $last ) {
		$expired = ! empty( $connection['expiresAt'] ) && strtotime( $connection['expiresAt'] ) && strtotime( $connection['expiresAt'] ) < time();
		echo '<h2>Status</h2><table class="widefat striped" style="max-width:640px"><tbody>';
		self::row( 'Service', isset( $connection['service'] ) ? $connection['service'] : SHC_Companion_Client::service() );
		self::row( 'Connected since', isset( $connection['connectedAt'] ) ? $connection['connectedAt'] : '' );
		self::row( 'Key expires', ( isset( $connection['expiresAt'] ) ? $connection['expiresAt'] : '' ) . ( $expired ? ' (expired: pair again)' : '' ) );
		if ( $last ) {
			self::row( 'Last report', $last['time'] . ': ' . ( $last['ok'] ? 'sent' : 'failed' ) . '. ' . $last['message'] );
		} else {
			self::row( 'Last report', 'None yet' );
		}
		echo '</tbody></table><p>';
		self::post_form( 'shc_companion_send', 'Send report now', 'button button-primary' );
		self::post_form( 'shc_companion_disconnect', 'Disconnect' );
		echo '</p>';
	}

	private static function row( $label, $value ) {
		echo '<tr><th scope="row">' . esc_html( $label ) . '</th><td>' . esc_html( $value ) . '</td></tr>';
	}
}
