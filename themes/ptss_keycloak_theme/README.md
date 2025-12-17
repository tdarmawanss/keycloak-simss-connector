# PTSS Keycloak Theme

Custom Keycloak theme for PTSS login pages with customizable logo and header.

## Theme Structure

```
ptss_keycloak_theme/
├── login/
│   ├── theme.properties          # Theme configuration
│   ├── template.ftl               # Custom login page template
│   └── resources/
│       ├── css/
│       │   └── custom.css         # Custom styles for logo and header
│       ├── img/
│       │   ├── logo.png           # YOUR CUSTOM LOGO (add this file)
│       │   └── favicon.ico        # Optional favicon
│       └── js/
└── README.md
```

## Quick Start

### 1. Add Your Logo

Place your logo image at:
```
themes/ptss_keycloak_theme/login/resources/img/logo.png
```

**Recommended logo specifications:**
- Format: PNG with transparent background
- Size: 300x80 pixels (or similar aspect ratio)
- The logo will auto-scale to fit

### 2. Customize Header and Colors

Edit `login/resources/css/custom.css` to customize:

- **Header background color**: Change `#kc-header-wrapper` background-color
- **Header border**: Modify `border-bottom` color in `#kc-header-wrapper`
- **Button colors**: Update `.btn-primary` background-color
- **Logo size**: Adjust `height` and `width` in `.login-pf-page .login-pf-brand`

### 3. Deploy to Keycloak

Copy the entire `ptss_keycloak_theme` folder to your Keycloak themes directory:

```bash
cp -r themes/ptss_keycloak_theme /path/to/keycloak/themes/
```

### 4. Enable the Theme in Keycloak

1. Login to Keycloak Admin Console
2. Navigate to your realm settings
3. Go to **Themes** tab
4. Select **ptss_keycloak_theme** from the "Login theme" dropdown
5. Click **Save**

## Development Mode

When developing the theme, disable caching by starting Keycloak with:

```bash
kc.sh start-dev --spi-theme-cache-themes=false --spi-theme-cache-templates=false
```

This allows you to see changes immediately without restarting Keycloak.

## Customization Options

### Custom Header Text

The header text is automatically pulled from your realm's display name. To customize:
1. Go to Keycloak Admin Console → Realm Settings
2. Update the "Display name" field

### Custom Page Title

Edit `template.ftl` and modify the `<h1 id="kc-page-title">` section.

### Additional Styling

All CSS customizations should be added to `login/resources/css/custom.css`.

### Adding JavaScript

1. Place JS files in `login/resources/js/`
2. Reference them in `theme.properties` using the `scripts` property

## Extending the Theme

This theme extends the base `keycloak` theme, inheriting all default templates and styles. You can override additional templates by creating them in the `login/` directory:

- `login.ftl` - Login form
- `register.ftl` - Registration form
- `login-reset-password.ftl` - Password reset
- `error.ftl` - Error page

## References

Based on Keycloak official documentation:
- [Keycloak Theme Customization](https://www.keycloak.org/ui-customization/themes)
- [Base Theme Templates](https://github.com/keycloak/keycloak/tree/main/themes/src/main/resources/theme/base/login)

## Support

For issues or questions about this theme, refer to the Keycloak documentation or the project maintainer.
