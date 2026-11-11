<?php
/**
 * Plugin Name:       Security Health Check Companion
 * Description:       Read-only inside view for Security Health Check: plugins, core file integrity, administrators and settings. It never changes your site.
 * Version:           0.1.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       shc-companion
 *
 * @package shc-companion
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'SHC_COMPANION_VERSION', '0.1.0' );

require_once __DIR__ . '/includes/class-shc-companion-protocol.php';
require_once __DIR__ . '/includes/class-shc-companion-collector.php';
require_once __DIR__ . '/includes/class-shc-companion-client.php';
require_once __DIR__ . '/includes/class-shc-companion-admin.php';

function shc_companion_activate() {
	if ( ! wp_next_scheduled( SHC_Companion_Client::CRON_HOOK ) ) {
		wp_schedule_event( time() + wp_rand( 300, 3600 ), 'daily', SHC_Companion_Client::CRON_HOOK );
	}
}
register_activation_hook( __FILE__, 'shc_companion_activate' );

function shc_companion_deactivate() {
	wp_clear_scheduled_hook( SHC_Companion_Client::CRON_HOOK );
}
register_deactivation_hook( __FILE__, 'shc_companion_deactivate' );

function shc_companion_cron() {
	if ( SHC_Companion_Client::connection() ) {
		SHC_Companion_Client::send_report();
	}
}
add_action( SHC_Companion_Client::CRON_HOOK, 'shc_companion_cron' );

if ( is_admin() ) {
	SHC_Companion_Admin::init();
}

if ( defined( 'WP_CLI' ) && WP_CLI ) {
	require_once __DIR__ . '/includes/class-shc-companion-cli.php';
	WP_CLI::add_command( 'shc', 'SHC_Companion_CLI' );
}
