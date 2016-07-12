<?php

require "vendor/autoload.php";

$methods = openssl_get_md_methods(true);
print_r($methods);