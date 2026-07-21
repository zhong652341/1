<?php
/**
 * PHP 一句话木马执行包装器
 *
 * 用法: php wrapper.php <webshell_path>
 *
 * 功能:
 * 1. 读取 stdin（Flask 转发 POST body），解析到 $_POST
 * 2. 加载 webshell 文件执行（支持 $_POST['xxx'] 和 php://input 两种模式）
 */
error_reporting(0);

// 读取 stdin（Flask 转发的 POST body）
$input = stream_get_contents(STDIN);

// 解析 URL-encoded 数据到 $_POST
// 使 $_POST['xxx'] 标准蚁剑模式可用
if ($input !== false && $input !== '') {
    parse_str($input, $_POST);
    $_REQUEST = array_merge($_GET, $_POST);
}

// 加载 webshell（此时 $_POST 已准备好）
if (isset($argv[1]) && file_exists($argv[1])) {
    require $argv[1];
}
