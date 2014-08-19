<?php
require_once('/var/simplesamlphp/lib/_autoload.php');
$as = new SimpleSAML_Auth_Simple('default-sp');
$as->requireAuth();

if(isset($_SESSION['the_file'])) {
    ?>
<form id="dss-request-form" method="post" action="https://alpha.rolosa.com:8443/eid-dss/protocol/simple">
    <input type="hidden" name="SignatureRequest" value="<?php print $_SESSION['the_file'];?>" />
    <input type="hidden" name="target" value="http://app1.rolosa.com/phpEIDtest/landing.php" />
    <input type="hidden" name="language" value="es" />
    <input type="hidden" name="ContentType" value="<?php print $_SESSION['file_type']; ?>" />
    <input type="hidden" name="RelayState" value="foo123" />
    <input type="submit" value="Submit" style="visibility: hidden;"/>
</form>
<script type="text/javascript">
    document.getElementById('dss-request-form').submit();
</script>
    <?php
}
?>

