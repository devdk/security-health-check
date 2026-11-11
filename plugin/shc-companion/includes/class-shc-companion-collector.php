<?php
/**
 * Builds the schema-1 report. Read-only: it never changes the site and never sends file contents.
 *
 * @package shc-companion
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class SHC_Companion_Collector {

	const LIST_CAP        = 100;
	const UPLOADS_SCANNED = 20000;
	const TREE_SCANNED    = 20000;
	const RECENT_DAYS     = 7;
	// Folders whose PHP files are routinely rewritten data or settings (firewall state, cache config), not code changes.
	const RECENT_PRUNE    = array( 'uploads', 'cache', 'upgrade', 'upgrade-temp-backup', 'languages', 'wflogs', 'w3tc-config', 'wp-rocket-config' );
	const RECENT_SKIP     = array( 'wp-cache-config.php' );

	private $deadline;
	private $plugin_main_files = array();

	public function __construct( $budget_seconds = 25 ) {
		$this->deadline = microtime( true ) + $budget_seconds;
	}

	public function collect( $plugin_version ) {
		list( $wp_version, $package_locale ) = self::installed_release();

		$plugins = $this->plugins();
		$themes  = $this->themes();

		return array(
			'schema'        => 1,
			'generatedAt'   => SHC_Companion_Protocol::iso_time( time() ),
			'plugin'        => array( 'version' => (string) SHC_Companion_Protocol::clean_version( $plugin_version ) ),
			'site'          => array(
				'homeUrl'   => home_url(),
				'siteUrl'   => site_url(),
				'multisite' => is_multisite(),
			),
			'wordpress'     => array(
				'version' => (string) SHC_Companion_Protocol::clean_version( $wp_version ),
				'locale'  => preg_replace( '/[^A-Za-z0-9_-]/', '', (string) get_locale() ),
			),
			'php'           => array( 'version' => (string) SHC_Companion_Protocol::clean_version( PHP_VERSION ) ),
			'plugins'       => $plugins,
			'themes'        => $themes,
			'admins'        => $this->admins(),
			'debug'         => $this->debug(),
			'configFile'    => $this->config_file(),
			'coreIntegrity' => $this->core_integrity( $wp_version, $package_locale ),
			'uploadsPhp'    => $this->uploads_php(),
			'recentPhp'     => $this->recent_php(),
		);
	}

	/**
	 * The installed version and the language of the installed package, read from version.php
	 * the way core's own update checks do. Checksums must match the package, not the Site
	 * Language setting, and a plugin that rewrites $wp_version can't skew them.
	 */
	private static function installed_release() {
		$wp_version       = '';
		$wp_local_package = null;
		include ABSPATH . WPINC . '/version.php';
		return array( (string) $wp_version, is_string( $wp_local_package ) && '' !== $wp_local_package ? $wp_local_package : 'en_US' );
	}

	public static function to_json( $payload, $pretty = false ) {
		$flags = JSON_UNESCAPED_SLASHES | ( $pretty ? JSON_PRETTY_PRINT : 0 );
		return wp_json_encode( $payload, $flags );
	}

	private function out_of_time() {
		return microtime( true ) > $this->deadline;
	}

	private function plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$auto = (array) get_site_option( 'auto_update_plugins', array() );
		$out  = array();
		foreach ( get_plugins() as $file => $data ) {
			$dir                              = dirname( $file );
			$slug                             = '.' === $dir ? basename( $file, '.php' ) : $dir;
			$this->plugin_main_files[ $slug ] = $file;
			if ( 'shc-companion' === $slug || 1 !== preg_match( '/\A[A-Za-z0-9._-]+\z/', $slug ) || count( $out ) >= 1000 ) {
				continue;
			}
			$out[] = array(
				'slug'       => $slug,
				'file'       => SHC_Companion_Protocol::clean_path( $file ),
				'name'       => SHC_Companion_Protocol::clean_text( $data['Name'], 300 ),
				'version'    => SHC_Companion_Protocol::clean_version( $data['Version'] ),
				'active'     => is_plugin_active( $file ) || is_plugin_active_for_network( $file ),
				'autoUpdate' => in_array( $file, $auto, true ),
			);
		}
		return $out;
	}

	private function themes() {
		$auto   = (array) get_site_option( 'auto_update_themes', array() );
		$active = get_stylesheet();
		$out    = array();
		foreach ( wp_get_themes() as $slug => $theme ) {
			if ( 1 !== preg_match( '/\A[A-Za-z0-9._-]+\z/', $slug ) || count( $out ) >= 200 ) {
				continue;
			}
			$template = $theme->get_template();
			$parent   = ( $template && $template !== $slug && 1 === preg_match( '/\A[A-Za-z0-9._-]+\z/', $template ) ) ? $template : null;
			$out[]    = array(
				'slug'       => $slug,
				'name'       => SHC_Companion_Protocol::clean_text( $theme->get( 'Name' ), 300 ),
				'version'    => SHC_Companion_Protocol::clean_version( $theme->get( 'Version' ) ),
				'active'     => $slug === $active,
				'parent'     => $parent,
				'autoUpdate' => in_array( $slug, $auto, true ),
			);
		}
		return $out;
	}

	private function admins() {
		$out   = array();
		$users = get_users(
			array(
				'role'    => 'administrator',
				'number'  => 500,
				'orderby' => 'ID',
				'order'   => 'ASC',
			)
		);
		foreach ( $users as $user ) {
			$roles = array();
			foreach ( (array) $user->roles as $role ) {
				if ( 1 === preg_match( '/\A[A-Za-z0-9_-]{1,64}\z/', $role ) ) {
					$roles[] = $role;
				}
			}
			$out[] = array(
				'login' => SHC_Companion_Protocol::mask( $user->user_login ),
				'roles' => array_slice( $roles, 0, 20 ),
			);
		}
		return $out;
	}

	private function debug() {
		$display = strtolower( (string) ini_get( 'display_errors' ) );
		return array(
			'wpDebug'        => defined( 'WP_DEBUG' ) && (bool) WP_DEBUG,
			'wpDebugDisplay' => defined( 'WP_DEBUG_DISPLAY' ) && (bool) WP_DEBUG_DISPLAY,
			'wpDebugLog'     => defined( 'WP_DEBUG_LOG' ) && (bool) WP_DEBUG_LOG,
			'displayErrors'  => in_array( $display, array( '1', 'on', 'true', 'yes', 'stdout', 'stderr' ), true ),
		);
	}

	private function config_file() {
		$above  = dirname( untrailingslashit( ABSPATH ) );
		$path   = null;
		$where  = null;
		// open_basedir can forbid looking above the WordPress root, hence the silenced calls.
		if ( @file_exists( ABSPATH . 'wp-config.php' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			$where = 'root';
			$path  = ABSPATH . 'wp-config.php';
		} elseif ( @file_exists( $above . '/wp-config.php' ) && ! @file_exists( $above . '/wp-settings.php' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			$where = 'parent';
			$path  = $above . '/wp-config.php';
		}
		$mode = null;
		if ( $path && '/' === DIRECTORY_SEPARATOR ) {
			$perms = @fileperms( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( false !== $perms ) {
				$mode = sprintf( '0%03o', $perms & 0777 );
			}
		}
		return array(
			'found'    => null !== $where,
			'location' => $where,
			'mode'     => $mode,
		);
	}

	private function core_integrity( $version, $package_locale ) {
		$result = array(
			'status'     => 'unavailable',
			'reason'     => null,
			'modified'   => array(),
			'missing'    => array(),
			'unexpected' => array(),
			'truncated'  => false,
		);

		if ( ! function_exists( 'get_core_checksums' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		$checksums = get_core_checksums( $version, $package_locale );
		if ( ! is_array( $checksums ) ) {
			$result['reason'] = 'Checksums for this WordPress version and locale could not be fetched from WordPress.org.';
			return $result;
		}

		$modified = array();
		$missing  = array();
		foreach ( $checksums as $file => $md5 ) {
			if ( 0 === strpos( $file, 'wp-content/' ) || ! is_string( $md5 ) ) {
				continue;
			}
			if ( $this->out_of_time() ) {
				$result['truncated'] = true;
				break;
			}
			$path = ABSPATH . $file;
			if ( ! is_file( $path ) ) {
				$missing[] = $file;
			} elseif ( md5_file( $path ) !== $md5 ) {
				$modified[] = $file;
			}
		}

		$unexpected = array();
		$scanned    = 0;
		foreach ( array( 'wp-admin', 'wp-includes' ) as $dir ) {
			foreach ( $this->files( ABSPATH . $dir ) as $rel => $info ) {
				if ( ++$scanned > self::TREE_SCANNED || $this->out_of_time() ) {
					$result['truncated'] = true;
					break 2;
				}
				$rel = $dir . '/' . $rel;
				if ( '.php' === strtolower( substr( $rel, -4 ) ) && ! isset( $checksums[ $rel ] ) ) {
					$unexpected[] = $rel;
				}
			}
		}

		$result['status']     = 'ok';
		$result['modified']   = $this->cap( $modified, $result['truncated'] );
		$result['missing']    = $this->cap( $missing, $result['truncated'] );
		$result['unexpected'] = $this->cap( $unexpected, $result['truncated'] );
		return $result;
	}

	private function uploads_php() {
		$uploads = wp_upload_dir( null, false );
		$out     = array(
			'files'     => array(),
			'scanned'   => 0,
			'truncated' => false,
		);
		if ( empty( $uploads['basedir'] ) ) {
			return $out;
		}
		// A symlinked PHP file in uploads still runs under Apache's FollowSymLinks, so list links too (never followed).
		foreach ( $this->files( $uploads['basedir'], null, true ) as $rel => $info ) {
			if ( $out['scanned'] >= self::UPLOADS_SCANNED || $this->out_of_time() ) {
				$out['truncated'] = true;
				break;
			}
			++$out['scanned'];
			if ( ! SHC_Companion_Protocol::is_php_extension( $rel ) ) {
				continue;
			}
			$size = (int) $info->getSize();
			if ( 'index.php' === basename( $rel ) && $size <= SHC_Companion_Protocol::SILENT_INDEX_MAX_BYTES && $this->silent_index( $info->getPathname() ) ) {
				continue;
			}
			if ( count( $out['files'] ) >= self::LIST_CAP ) {
				$out['truncated'] = true;
				break;
			}
			$out['files'][] = array(
				'path'       => SHC_Companion_Protocol::clean_path( $rel ),
				'size'       => $size,
				'modifiedAt' => SHC_Companion_Protocol::iso_time( $info->getMTime() ),
			);
		}
		return $out;
	}

	/** The only file content this plugin ever reads: at most 201 bytes of an index.php. */
	private function silent_index( $path ) {
		$content = @file_get_contents( $path, false, null, 0, SHC_Companion_Protocol::SILENT_INDEX_MAX_BYTES + 1 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		return false !== $content && SHC_Companion_Protocol::is_silent_index( $content );
	}

	private function recent_php() {
		$out    = array(
			'days'      => self::RECENT_DAYS,
			'files'     => array(),
			'truncated' => false,
		);
		$since  = time() - self::RECENT_DAYS * DAY_IN_SECONDS;
		$found  = array();
		$looked = 0;
		$prune  = function ( $rel ) {
			return in_array( $rel, self::RECENT_PRUNE, true );
		};
		foreach ( $this->files( WP_CONTENT_DIR, $prune ) as $rel => $info ) {
			if ( ++$looked > self::TREE_SCANNED || $this->out_of_time() ) {
				$out['truncated'] = true;
				break;
			}
			if ( '.php' !== strtolower( substr( $rel, -4 ) ) || in_array( $rel, self::RECENT_SKIP, true ) ) {
				continue;
			}
			$mtime = (int) $info->getMTime();
			if ( $mtime >= $since ) {
				$found[ $rel ] = $mtime;
			}
		}
		// Files that don't look like an update come first: a fresh install must not crowd them out of the capped list.
		$entries = array();
		foreach ( $found as $rel => $mtime ) {
			$entries[] = array(
				'path'           => SHC_Companion_Protocol::clean_path( $rel ),
				'modifiedAt'     => SHC_Companion_Protocol::iso_time( $mtime ),
				'packageUpdated' => SHC_Companion_Protocol::package_updated( $this->marker_mtime( $rel ), $mtime ),
				'mtime'          => $mtime,
			);
		}
		usort(
			$entries,
			function ( $a, $b ) {
				return array( $a['packageUpdated'], -$a['mtime'] ) <=> array( $b['packageUpdated'], -$b['mtime'] );
			}
		);
		if ( count( $entries ) > self::LIST_CAP ) {
			$out['truncated'] = true;
			$entries          = array_slice( $entries, 0, self::LIST_CAP );
		}
		foreach ( $entries as $entry ) {
			unset( $entry['mtime'] );
			$out['files'][] = $entry;
		}
		return $out;
	}

	private function marker_mtime( $path_in_content ) {
		$package = SHC_Companion_Protocol::package_of( $path_in_content );
		if ( null === $package ) {
			return null;
		}
		list( $type, $slug ) = $package;
		if ( 'themes' === $type ) {
			$marker = WP_CONTENT_DIR . '/themes/' . $slug . '/style.css';
		} elseif ( isset( $this->plugin_main_files[ $slug ] ) ) {
			$marker = WP_PLUGIN_DIR . '/' . $this->plugin_main_files[ $slug ];
		} else {
			return null;
		}
		$mtime = @filemtime( $marker ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		return false === $mtime ? null : $mtime;
	}

	private function cap( $list, &$truncated ) {
		sort( $list );
		if ( count( $list ) > self::LIST_CAP ) {
			$truncated = true;
			$list      = array_slice( $list, 0, self::LIST_CAP );
		}
		return array_map( array( 'SHC_Companion_Protocol', 'clean_path' ), $list );
	}

	/**
	 * Regular files under $root, keyed by path relative to it. Symlinked folders are never followed.
	 *
	 * @param string        $root       Directory to walk.
	 * @param callable|null $prune      Receives a directory's relative path; true skips it.
	 * @param bool          $file_links Also list symlinks to files (they are not opened).
	 */
	private function files( $root, $prune = null, $file_links = false ) {
		$root = rtrim( wp_normalize_path( $root ), '/' );
		if ( ! is_dir( $root ) ) {
			return;
		}
		$offset = strlen( $root ) + 1;
		try {
			$dir    = new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS | FilesystemIterator::UNIX_PATHS );
			$filter = new RecursiveCallbackFilterIterator(
				$dir,
				function ( $current ) use ( $prune, $offset, $file_links ) {
					if ( $current->isLink() ) {
						return $file_links && ! $current->isDir();
					}
					return ! ( $prune && $current->isDir() && $prune( substr( $current->getPathname(), $offset ) ) );
				}
			);
			$walk   = new RecursiveIteratorIterator( $filter, RecursiveIteratorIterator::LEAVES_ONLY, RecursiveIteratorIterator::CATCH_GET_CHILD );
			foreach ( $walk as $info ) {
				if ( $info->isFile() ) {
					yield substr( $info->getPathname(), $offset ) => $info;
				}
			}
		} catch ( Exception $e ) {
			return;
		}
	}
}
