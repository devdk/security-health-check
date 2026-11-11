<?php
/**
 * Dependency-free tests for the protocol class. Run: php plugin/tests/run.php
 */

define( 'SHC_COMPANION_TESTS', true );
require __DIR__ . '/../shc-companion/includes/class-shc-companion-protocol.php';

$passed   = 0;
$failures = array();

function check( $name, $actual, $expected ) {
	global $passed, $failures;
	if ( $actual === $expected ) {
		++$passed;
		return;
	}
	$failures[] = $name . "\n    expected: " . var_export( $expected, true ) . "\n    actual:   " . var_export( $actual, true );
}

$vectors = json_decode( file_get_contents( __DIR__ . '/../../packages/companion/test/vectors.json' ), true );
if ( ! is_array( $vectors ) ) {
	fwrite( STDERR, "vectors.json could not be read\n" );
	exit( 1 );
}

foreach ( $vectors['signatures'] as $i => $v ) {
	$label = 'signature vector ' . $i;
	check( $label . ' bodySha256', SHC_Companion_Protocol::body_sha256( $v['body'] ), $v['bodySha256'] );
	check( $label . ' stringToSign', SHC_Companion_Protocol::string_to_sign( $v['method'], $v['path'], $v['timestamp'], $v['nonce'], $v['body'] ), $v['stringToSign'] );
	check( $label . ' signature', SHC_Companion_Protocol::signature( $v['key'], $v['method'], $v['path'], $v['timestamp'], $v['nonce'], $v['body'] ), $v['signature'] );
}

foreach ( $vectors['mask'] as $v ) {
	check( 'mask ' . var_export( $v['input'], true ), SHC_Companion_Protocol::mask( $v['input'] ), $v['masked'] );
}

$silent = array(
	array( "<?php\n// Silence is golden.\n", true ),
	array( '<?php // Silence is golden.', true ),
	array( "<?php\n// Silence is golden", true ),
	array( "<?php\n// Silence is golden.\n?>\n", true ),
	array( '<?php', true ),
	array( "<?php\n", true ),
	array( "<?php ?>\n", true ),
	array( '<?php system($_GET["c"]);', false ),
	array( "<?php\n// Silence is golden.\neval(\$_POST['x']);", false ),
	array( "<?php\n// Silence is silver.\n", false ),
	array( "<?php\n/* Silence is golden. */", false ),
	array( "x<?php\n// Silence is golden.\n", false ),
	array( '', false ),
	array( "<?php\n// Silence is golden.\n" . str_repeat( ' ', 200 ), false ),
);
foreach ( $silent as $i => $case ) {
	check( 'silent index ' . $i, SHC_Companion_Protocol::is_silent_index( $case[0] ), $case[1] );
}

check( 'package updated, same time', SHC_Companion_Protocol::package_updated( 1000, 1000 ), true );
check( 'package updated, marker 1h before', SHC_Companion_Protocol::package_updated( 1000, 1000 + 3600 ), true );
check( 'package updated, marker 1h after', SHC_Companion_Protocol::package_updated( 1000 + 3600, 1000 ), true );
check( 'package updated, just over an hour', SHC_Companion_Protocol::package_updated( 1000, 1000 + 3601 ), false );
check( 'package updated, no marker', SHC_Companion_Protocol::package_updated( null, 1000 ), false );

check( 'package of plugin file', SHC_Companion_Protocol::package_of( 'plugins/foo/inc/a.php' ), array( 'plugins', 'foo' ) );
check( 'package of theme file', SHC_Companion_Protocol::package_of( 'themes/bar/functions.php' ), array( 'themes', 'bar' ) );
check( 'package of single-file plugin', SHC_Companion_Protocol::package_of( 'plugins/hello.php' ), null );
check( 'package of mu-plugin', SHC_Companion_Protocol::package_of( 'mu-plugins/x.php' ), null );

foreach ( array( 'a.php', 'A.PHP', 'a.phtml', 'a.php3', 'a.php8', 'a.phar', 'a.pht', 'x/y.Php5' ) as $name ) {
	check( 'php extension ' . $name, SHC_Companion_Protocol::is_php_extension( $name ), true );
}
foreach ( array( 'a.php9', 'a.php.jpg', 'a.png', 'php', 'a.phpx' ) as $name ) {
	check( 'not php extension ' . $name, SHC_Companion_Protocol::is_php_extension( $name ), false );
}

$nonces = array();
for ( $i = 0; $i < 50; $i++ ) {
	$nonces[] = SHC_Companion_Protocol::nonce();
}
check( 'nonce format', count( array_filter( $nonces, function ( $n ) {
	return 1 === preg_match( '/\A[A-Za-z0-9_-]{16,64}\z/', $n );
} ) ), 50 );
check( 'nonce uniqueness', count( array_unique( $nonces ) ), 50 );

check( 'clean_version keeps valid', SHC_Companion_Protocol::clean_version( '5.3.1-beta+1' ), '5.3.1-beta+1' );
check( 'clean_version strips', SHC_Companion_Protocol::clean_version( ' 1.2 (x) ' ), '1.2x' );
check( 'clean_version empty', SHC_Companion_Protocol::clean_version( '' ), null );
check( 'clean_text control chars', SHC_Companion_Protocol::clean_text( "a\nb\x00c", 10 ), 'a b c' );
check( 'clean_text truncates by characters', SHC_Companion_Protocol::clean_text( 'éééé', 2 ), 'éé' );
check( 'clean_text invalid utf8', SHC_Companion_Protocol::clean_text( "a\xffb", 10 ), 'a?b' );
check( 'clean_path', SHC_Companion_Protocol::clean_path( "/x\\y\nz.php" ), 'x/y z.php' );
check( 'iso_time', SHC_Companion_Protocol::iso_time( 1794400000 ), '2026-11-11T12:26:40Z' );

if ( $failures ) {
	fwrite( STDERR, count( $failures ) . " failed, $passed passed\n" . implode( "\n", $failures ) . "\n" );
	exit( 1 );
}
echo "$passed checks passed\n";
