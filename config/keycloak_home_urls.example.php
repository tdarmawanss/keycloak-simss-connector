<?php
/**
 * Role-Based Home URL Configuration Example
 * 
 * Copy this file to your application's config directory as:
 * - application/config/keycloak_home_urls.php
 * 
 * Or for subdomain-specific configurations:
 * - application/config/keycloak_home_urls_pkh.php
 * - application/config/keycloak_home_urls_lks.php
 * 
 * This configuration maps user roles to their respective home URLs.
 * When a user logs in, they will be redirected to the URL associated
 * with their role. If a user has multiple roles, the first matching
 * role (in order) will be used.
 * 
 * Format:
 * - Keys are role names (case-insensitive matching)
 * - Values are URLs relative to base_url() or absolute URLs
 * - 'default' key is used as fallback if no role matches
 * 
 * Example:
 * - Role 'supervisor' → '/supervisor'
 * - Role 'staff' → '/staff/home'
 * - No matching role → '/home' (default)
 */

$config['keycloak_home_urls'] = [
    // Role-based home URLs (in priority order)
    // First matching role will be used
    
    // Administrator roles
    'super_admin' => 'admin/dashboard',
    'administrator' => 'admin',
    
    // Manager roles
    'supervisor' => 'supervisor',
    'manager' => 'manager/home',
    
    // Staff roles
    'staff' => 'staff/dashboard',
    'viewer' => 'home',
    
    // Default home URL if no role matches
    'default' => 'home',
];
