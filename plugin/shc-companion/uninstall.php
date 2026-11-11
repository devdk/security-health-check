<?php
/**
 * Removes everything the plugin stored.
 *
 * @package shc-companion
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

delete_option( 'shc_companion_service' );
delete_option( 'shc_companion_connection' );
delete_option( 'shc_companion_last' );
wp_clear_scheduled_hook( 'shc_companion_daily_report' );
