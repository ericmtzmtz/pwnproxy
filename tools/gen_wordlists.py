"""Regenerate wordlist .txt files — comprehensive pentest paths."""
import pathlib

BASE = pathlib.Path("pwnproxy/services/crawler/wordlists")


def dedup_sort(entries):
    seen = set()
    result = []
    for e in entries:
        e = e.strip().strip("/")
        if e and e not in seen:
            seen.add(e)
            result.append(e)
    return sorted(result)


def write_list(path, entries):
    deduped = dedup_sort(entries)
    path.write_text("\n".join(deduped) + "\n")
    return len(deduped)


# ═══════════════════════════════════════════════════════════════════════
# SMALL — Core paths only (~500)
# ═══════════════════════════════════════════════════════════════════════
small = [
    # Dotfiles / hidden
    ".env", ".env.bak", ".env.local", ".env.production", ".env.staging",
    ".env.old", ".env.save", ".env.example", ".env.dev", ".env.test",
    ".git/HEAD", ".git/config", ".gitignore", ".gitattributes",
    ".svn/entries", ".svn/wc.db", ".hg", "CVS",
    ".htaccess", ".htpasswd", ".well-known/security.txt",
    ".well-known/openid-configuration",
    ".well-known/assetlinks.json", ".well-known/change-password",
    ".well-known/host-meta", ".well-known/apple-app-site-association",
    # Sensitive files
    "crossdomain.xml", "clientaccesspolicy.xml", "web.config",
    "web.config.bak", "web.config.old", "web.xml",
    "robots.txt", "sitemap.xml", "humans.txt", "security.txt",
    "favicon.ico", "readme.html", "README.md", "LICENSE", "CHANGELOG",
    # Config / build
    "config.php", "config.php.bak", "config.json", "config.yml",
    "config.yaml", "config.xml", "config.ini", "configuration.php",
    "settings.py", "database.yml", "application.properties",
    "application.yml", "appsettings.json", "appsettings.Development.json",
    "package.json", "composer.json", "composer.lock", "Gemfile",
    "Gemfile.lock", "requirements.txt", "setup.py", "pyproject.toml",
    "pom.xml", "build.gradle", "build.gradle.kts", "Makefile",
    "Vagrantfile", "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".dockerignore", "Procfile", "Gruntfile.js", "Gulpfile.js",
    "webpack.config.js", "go.mod", "go.sum",
    # CI/CD
    ".github/workflows", ".github/actions", ".gitlab-ci.yml",
    ".circleci/config.yml", ".travis.yml", "Jenkinsfile",
    "azure-pipelines.yml", ".drone.yml", "bitbucket-pipelines.yml",
    "buildspec.yml", "cloudbuild.yaml",
    # Core directories
    "admin", "administrator", "admin.php", "adminer", "backoffice",
    "panel", "dashboard", "console", "manager", "manager/html",
    "manager/status", "webmail", "login", "login.php", "signin",
    "signup", "register", "register.php", "forgot", "password",
    "reset", "auth", "logout",
    # API
    "api", "api/v1", "api/v2", "api/v3", "api/v4", "api/v5",
    "api-docs", "api/docs", "api/swagger", "api/debug",
    "api/health", "api/status", "api/info", "api/version",
    "api/config", "api/users", "api/projects", "api/auth",
    "api/login", "api/me", "api/search", "api/token", "api/register",
    "graphql", "graphql/console",
    # Swagger / OpenAPI
    "swagger", "swagger-ui", "swagger-ui.html", "swagger.json",
    "swagger.yaml", "swagger/resources",
    "swagger-resources", "swagger-resources/configuration/ui",
    "swagger-resources/configuration/security",
    "openapi.json", "openapi.yaml",
    # Spring Boot actuator
    "actuator", "actuator/env", "actuator/health", "actuator/beans",
    "actuator/configprops", "actuator/mappings", "actuator/trace",
    "actuator/heapdump", "actuator/threaddump", "actuator/info",
    "actuator/prometheus", "actuator/conditions", "actuator/shutdown",
    "actuator/logfile", "actuator/loggers", "actuator/metrics",
    "actuator/auditevents", "actuator/caches", "actuator/dump",
    "actuator/scheduledtasks", "actuator/sessions", "actuator/httptrace",
    # CMS: WordPress
    "wp-admin", "wp-admin/install.php", "wp-admin/setup-config.php",
    "wp-admin/includes", "wp-admin/js", "wp-admin/plugins.php",
    "wp-admin/themes.php", "wp-admin/users.php", "wp-admin/edit.php",
    "wp-admin/options-general.php", "wp-admin/export.php",
    "wp-admin/import.php", "wp-admin/tools.php",
    "wp-content", "wp-content/debug.log", "wp-content/plugins",
    "wp-content/themes", "wp-content/uploads", "wp-content/upgrade",
    "wp-content/cache",
    "wp-includes", "wp-includes/js", "wp-includes/css",
    "wp-includes/images", "wp-json", "wp-json/wp/v2/users",
    "wp-json/wp/v2/posts", "wp-json/wp/v2/pages",
    "wp-json/wp/v2/comments", "wp-json/wp/v2/media",
    "wp-login.php", "wp-cron.php", "wp-comments-post.php",
    "wp-load.php", "wp-signup.php", "xmlrpc.php",
    # CMS: Drupal
    "core/install.php", "core/rebuild.php", "core/update.php",
    "sites/default/settings.php", "sites/default/files",
    "CHANGELOG.txt", "user/login", "user/register", "user/password",
    "admin/content", "admin/structure", "admin/config", "admin/people",
    # CMS: Joomla
    "administrator/index.php", "administrator/login.php",
    "administrator/manifests",
    # CMS: Magento
    "Mage.php", "app/etc/local.xml",
    # Laravel
    "artisan", "public/index.php", "bootstrap/cache",
    "storage/logs/laravel.log", "storage/framework/sessions",
    "storage/framework/views", "storage/framework/cache",
    "config/database.php", "config/app.php",
    "routes/web.php", "routes/api.php",
    ".env.development", ".env.testing",
    # Django
    "__debug__/", "static/admin", "admin/jsi18n",
    "api/v1/schema", "db.sqlite3",
    # .NET / IIS
    "default.aspx", "global.asax", "handler.ashx",
    "App_Data", "aspnet_client", "iisstart.htm",
    # Tomcat
    "host-manager/html", "manager/text/list",
    "manager/text/deploy", "manager/text/sessions",
    # Jenkins
    "jenkins/login", "jenkins/script", "jenkins/manage",
    "jenkins/api/json", "jenkins/crumbIssuer/api/json",
    # GitLab
    "api/v4/projects", "api/v4/users", "api/v4/groups",
    "users/sign_in", "-/graphql-explorer",
    # Confluence / Jira
    "wiki/pages/viewpage.action", "login.action",
    "rest/api/content", "rest/api/space",
    "jira/login.jsp", "rest/api/latest", "secure/Dashboard.jspa",
    # Exchange / OWA
    "owa", "ecp", "ews/Exchange.asmx",
    "autodiscover/autodiscover.xml",
    # SharePoint
    "_vti_bin", "_vti_inf.html", "_vti_pvt",
    # Cloud metadata
    "latest/meta-data/", "latest/meta-data/instance-id",
    "latest/meta-data/hostname", "latest/meta-data/local-ipv4",
    "latest/meta-data/public-ipv4", "latest/meta-data/instance-type",
    "latest/meta-data/ami-id", "latest/meta-data/placement/",
    "latest/meta-data/iam/security-credentials/",
    "latest/meta-data/iam/security-credentials/global",
    "latest/dynamic/instance-identity/document",
    "latest/user-data",
    # Monitoring
    "grafana/login", "grafana/api/dashboards", "grafana/api/health",
    "kibana/app/discover", "kibana/api/status",
    "prometheus/api/v1/query", "prometheus/api/v1/targets",
    "prometheus/graph",
    "alertmanager/api/v2/alerts",
    "consul/v1/agent/self", "consul/ui",
    "etcd/v2/keys", "etcd/version",
    "vault/v1/sys/health",
    "nexus/service/rest/v1/search", "nexus/service/rest/v1/status",
    "artifactory/api/system/ping",
    "sonarqube/api/system/status", "sonarqube/dashboard",
    # Misc pentest
    "backup", "backups", "db", "data", "database.sql", "dump.sql",
    "backup.sql", "data.sql", "test", "test.php", "info.php",
    "phpinfo.php", "debug.php", "debug",
    "uploads", "upload", "images", "img", "media", "static",
    "assets", "css", "js", "fonts", "vendor", "node_modules",
    "src", "lib", "bin", "tmp", "temp", "cache",
    "old", "new", "archive", "private", "internal",
    "logs", "log", "export", "import",
    "home", "portal", "status", "health", "healthcheck",
    "help", "info", "version", "server-status", "server-info",
    "cgi-bin", "cgi-bin/test.cgi",
    # Shell backdoors
    "shell.php", "cmd.php", "c99.php", "r57.php",
    # Misc
    "elmah.axd", "trace.axd",
    ".bash_history", ".mysql_history",
]

# ═══════════════════════════════════════════════════════════════════════
# MEDIUM — Extends small (~3000)
# ═══════════════════════════════════════════════════════════════════════
medium = list(small)

# WordPress deeper
medium.extend([
    "wp-content/plugins/akismet", "wp-content/plugins/wordfence",
    "wp-content/plugins/yoast-seo", "wp-content/plugins/jetpack",
    "wp-content/plugins/contact-form-7", "wp-content/plugins/woocommerce",
    "wp-content/plugins/elementor", "wp-content/plugins/akismet/readme.txt",
    "wp-content/themes/twentytwentyfour", "wp-content/themes/twentytwentythree",
    "wp-content/themes/twentytwentytwo", "wp-content/themes/twentytwentyone",
    "wp-content/themes/twentytwenty", "wp-content/themes/twentyfifteen",
    "wp-content/uploads/2024", "wp-content/uploads/2023",
    "wp-content/uploads/2022", "wp-content/uploads/2021",
    "wp-includes/rest-api", "wp-includes/Requests",
    "wp-includes/SimplePie", "wp-includes/sodium_compat",
    "wp-includes/js/tinymce", "wp-includes/css/buttons",
    "wp-json/wp/v2/taxonomies", "wp-json/wp/v2/categories",
    "wp-json/wp/v2/tags",
    "wp-activate.php", "wp-trackback.php", "wp-mail.php",
    "readme.html", "license.txt",
])

# Laravel deeper
medium.extend([
    "storage/app", "storage/app/public", "vendor/autoload.php",
    "vendor/laravel/framework", "app/Http/Kernel.php",
    "app/Providers", "bootstrap/app.php",
    "config/mail.php", "config/services.php", "config/queue.php",
    "config/logging.php", "config/cache.php", "config/session.php",
    "config/auth.php", "config/filesystems.php",
    "storage/logs", "storage/debugbar",
])

# Drupal deeper
medium.extend([
    "core/modules", "core/themes", "core/profiles",
    "modules/README.txt", "profiles/README.txt",
    "sites/all/modules", "sites/all/themes",
    "sites/default/files/private",
    "node/add", "node/1", "node/feed",
    "admin/modules", "admin/themes", "admin/config/system",
    "admin/structure/types", "admin/structure/views",
    "admin/config/search", "admin/config/media",
    "admin/config/content", "admin/config/user-interface",
    "cron.php", "update.php", "authorize.php",
])

# Joomla deeper
medium.extend([
    "components/com_content", "components/com_users",
    "components/com_contact", "components/com_finder",
    "modules/mod_login", "modules/mod_menu", "modules/mod_search",
    "plugins/authentication", "plugins/content", "plugins/system",
    "language/en-GB", "templates/protostar", "templates/beez3",
    "installation/", "administrator/components",
    "administrator/modules", "administrator/templates",
])

# Magento deeper
medium.extend([
    "magento/backend", "skin/frontend", "media/catalog",
    "downloader/", "downloader/Maged",
    "app/Mage.php", "app/code/core/Mage",
    "app/code/community", "app/design/frontend",
    "app/design/adminhtml", "lib/Magento", "lib/Varien",
    "js/mage", "media/customer", "media/downloadable",
    "var/log", "var/session", "var/cache",
])

# Exchange / OWA deeper
medium.extend([
    "ecp/rules", "ecp/users", "ecp/organizationalrelationships",
    "ecp/hybridmailflow", "ecp/services",
    "ews/exchange.asmx", "ews/soap",
    "mapi/emsmdb/", "mapi/nspi/",
    "autodiscover/autodiscover.json",
    "microsoft-Server-ActiveSync",
    "owa/owaerror", "powershell?ps1=",
])

# SharePoint deeper
medium.extend([
    "_vti_bin/_vti_aut", "_vti_bin/alerts",
    "_vti_bin/dws", "_vti_bin/layouts", "_vti_bin/lists",
    "sharepoint", "sites", "teams",
])

# Confluence deeper
medium.extend([
    "rest/api/user", "rest/api/space", "rest/api/content",
    "wiki/pages/viewpage.action", "login.action",
    "server-info", "status",
])

# Jira deeper
medium.extend([
    "secure/AdminBrowseProjects.jspa", "secure/admin",
    "rest/api/latest/project", "rest/api/latest/user",
    "rest/myself",
])

# ADFS / SAP
medium.extend([
    "adfs/ls/", "adfs/proxy",
    "adfs/.well-known/openid-configuration",
    "sap/bc/gui", "sap/public/ping", "sap/bc/ping", "sap/bc/adt",
])

# Nexus / Artifactory / SonarQube
medium.extend([
    "nexus/service/rest/v1/repositories", "nexus/content",
    "nexus/repository/maven-public/",
    "artifactory/api/repositories", "artifactory/ui",
    "artifactory/webapp", "artifactory/api/search",
    "sonarqube/api/projects", "sonarqube/api/rules",
    "sonarqube/dashboard", "sonarqube/api/issues",
    "sonarqube/api/qualityprofiles",
])

# Grafana deeper
medium.extend([
    "grafana/api/datasources", "grafana/d",
    "grafana/explore", "grafana/snapshotting",
    "grafana/api/annotations", "grafana/api/search",
])

# Kibana deeper
medium.extend([
    "kibana/login", "kibana/api/status",
    "kibana/app/management", "kibana/app/dev_tools",
    "kibana/api/saved_objects",
])

# Prometheus deeper
medium.extend([
    "prometheus/api/v1/status/config",
    "prometheus/api/v1/status/runtimeinfo",
    "prometheus/api/v1/status/flags",
    "prometheus/api/v1/label/__name__/values",
])

# Alertmanager / Consul / Etcd / Vault
medium.extend([
    "alertmanager/api/v2/silences",
    "consul/v1/catalog", "consul/v1/kv",
    "consul/v1/health/service",
    "etcd/v3/kv", "etcd/v3/cluster",
    "vault/v1/secret", "vault/v1/sys/mounts",
    "vault/v1/sys/policies", "vault/ui",
])

# Debug / profiling
medium.extend([
    "__debug__/", "debug/default/view", "debug/vars",
    "debug/pprof", "debug/requests",
    "_profiler", "profiler",
    "elmah.axd/detail", "elmah.axd/errorlog",
])

# Backup / data files
medium.extend([
    "www.zip", "web.zip", "source.zip", "code.zip", "html.zip",
    "db.zip", "backup.zip", "site.tar.gz", "backup.tar.gz",
    "www.tar.gz", "web.tar.gz", "source.tar.gz",
    "database.sql.bak", "dump.sql.bak", "data.sql.bak",
    "config.php.bak", "wp-config.php.bak",
    "backup.sql.gz", "dump.sql.gz", "db.sql.gz",
    "www.backup", "web.backup", "site.backup",
])

# Server files
medium.extend([
    "error_log", "access_log", "debug.log", "error.log",
    "server.log", "app.log", "application.log",
    "php_errors.log", "nginx-error.log",
])

# More pentest paths
medium.extend([
    "server-status", "server-info",
    "cgi-bin/test-cgi", "cgi-bin/env.cgi",
    "cgi-bin/printenv", "cgi-bin/shell.cgi",
    "cgi-bin/Count.cgi", "cgi-bin/phf",
    "iisstart.htm", "iis-85.png", "iis-75.png",
    "aspnet_client/system_web",
    "web-inf/web.xml", "web-inf/classes",
    "meta-inf/manifest.mf",
    "browserconfig.xml", "manifest.json",
    "service-worker.js", "sitemap_index.xml",
    "clientaccesspolicy.xml",
    "robots.txt.bak", "robots.txt.old",
    ".env.backup", ".env.swp", ".env.swo",
    ".env.local.bak", ".env.production.bak",
    "database.yml.bak", "settings.py.bak",
    ".htaccess.bak", ".htpasswd.bak",
])

# Docker / K8s
medium.extend([
    "docker-compose.override.yml",
    "k8s/deployment.yaml", "k8s/service.yaml",
    "manifests/deployment.yaml",
    "helm/Chart.yaml", "helm/values.yaml",
    "charts/", "deploy/",
])

# More CI/CD
medium.extend([
    ".github/dependabot.yml", ".github/workflows/ci.yml",
    ".github/workflows/deploy.yml", ".github/workflows/release.yml",
    ".github/CODEOWNERS", ".github/FUNDING.yml",
    "Jenkinsfile.declarative", "Jenkinsfile.script",
    ".gitlab-ci-staging.yml", ".gitlab-ci-production.yml",
    ".drone.star",
])

# Dev/staging/environments
medium.extend([
    "staging/api", "staging/admin", "preprod", "uat",
    "intranet", "corporate", "dev/api", "dev/admin",
    "test/api", "test/admin", "sandbox", "demo",
    "beta", "alpha", "rc", "canary",
])

# Languages / frameworks
medium.extend([
    "Pipfile.lock", "MANIFEST.in", "pytest.ini",
    "conftest.py", "tox.ini", "setup.cfg",
    "runtime.txt", "phpunit.xml.dist",
    "phpstan.neon", "psalm.xml", "phpcs.xml",
    ".ruby-version", "config.ru", "Rakefile",
    "Thorfile", "Berksfile", "Vagrantfile",
    "chef/", "puppet/", "ansible/",
    ".editorconfig", ".eslintrc", ".prettierrc",
    "tsconfig.json", "jest.config.js",
    ".babelrc", "babel.config.js",
])

# ═══════════════════════════════════════════════════════════════════════
# LARGE — Extends medium (large = list(medium) placed after all medium adds)
# ═══════════════════════════════════════════════════════════════════════
_large_extra = []

# WordPress deeper
_large_extra.extend([
    "wp-content/plugins/all-in-one-seo-pack", "wp-content/plugins/advanced-custom-fields",
    "wp-content/plugins/updraftplus", "wp-content/plugins/redirection",
    "wp-content/plugins/wpforms-lite", "wp-content/plugins/litespeed-cache",
    "wp-content/plugins/sitekit-by-google", "wp-content/plugins/antispam-bee",
    "wp-content/plugins/wp-super-cache", "wp-content/plugins/bbpress",
    "wp-content/plugins/buddypress", "wp-content/plugins/nextgen-gallery",
    "wp-content/plugins/woocommerce/readme.txt", "wp-content/plugins/elementor/readme.txt",
    "wp-content/themes/flavor", "wp-content/themes/flavor-developer",
    "wp-content/themes/flavor-developer/readme.txt",
    "wp-content/debug.log.bak", "wp-content/advanced-cache.php",
    "wp-content/object-cache.php", "wp-content/drop-ins",
    "wp-admin/includes/export.php", "wp-admin/includes/import.php",
    "wp-admin/includes/file.php", "wp-admin/includes/plugin.php",
    "wp-admin/includes/theme.php", "wp-admin/includes/user.php",
    "wp-admin/includes/post.php", "wp-admin/includes/media.php",
    "wp-admin/includes/meta-boxes.php", "wp-admin/includes/template.php",
    "wp-admin/includes/admin.php", "wp-admin/includes/menu.php",
    "wp-admin/includes/misc.php", "wp-admin/includes/upgrade.php",
    "wp-admin/includes/class-wp-upgrader.php",
    "wp-includes/class-wp.php", "wp-includes/class-wpdb.php",
    "wp-includes/class-wp-error.php", "wp-includes/class-wp-http.php",
    "wp-includes/class-wp-xmlrpc-server.php",
    "wp-includes/formatting.php", "wp-includes/pluggable.php",
    "wp-includes/canonical.php", "wp-includes/general-template.php",
    "wp-includes/link-template.php", "wp-includes/option.php",
    "wp-includes/post.php", "wp-includes/taxonomy.php",
    "wp-includes/user.php", "wp-includes/comment.php",
    "wp-includes/category-template.php", "wp-includes/widgets.php",
    "wp-includes/query.php", "wp-includes/cache.php",
    "wp-includes/theme.php", "wp-includes/plugin.php",
    "wp-includes/script-loader.php", "wp-includes/admin-bar.php",
    "wp-includes/ms-functions.php", "wp-includes/ms-site.php",
    "wp-includes/winks.php", "wp-includes/http.php",
    "wp-includes/class-simplepie.php",
    "wp-json/wp/v2/menu-items", "wp-json/wp/v2/templates",
    "wp-json/wp/v2/themes", "wp-json/wp/v2/block-types",
    "wp-json/wp/v2/global-styles", "wp-json/wp/v2/pattern-directory",
])

# Drupal comprehensive
_large_extra.extend([
    "core/lib/Drupal.php", "core/lib/Drupal/Core/Database/Database.php",
    "core/lib/Drupal/Core/Entity/Entity.php",
    "core/lib/Drupal/Core/Session/AccountInterface.php",
    "core/modules/system", "core/modules/user", "core/modules/node",
    "core/modules/comment", "core/modules/taxonomy",
    "core/modules/field", "core/modules/field_ui",
    "core/modules/views", "core/modules/views/config",
    "core/modules/search", "core/modules/shortcut",
    "core/modules/block", "core/modules/menu_ui",
    "core/modules/toolbar", "core/modules/overlay",
    "core/modules/ckeditor", "core/modules/aggregator",
    "core/modules/book", "core/modules/contact",
    "core/modules/dblog", "core/modules/hal",
    "core/modules/history", "core/modules/locale",
    "core/modules/media", "core/modules/metatag",
    "core/modules/migrate", "core/modules/node/src",
    "core/modules/rdf", "core/modules/responsive_image",
    "core/modules/search/src", "core/modules/serialization",
    "core/modules/simpletest", "core/modules/system/tests",
    "core/modules/text", "core/modules/tour",
    "core/modules/update", "core/modules/views_ui",
    "modules/simpletest/tests", "profiles/",
    "sites/all/libraries", "sites/default/files/private/",
    "sites/default/private", "sites/default/files/tmp",
    "sites/default/files/css", "sites/default/files/js",
    "sites/default/files/images",
    "authorize.php", "cron.php", "install.php",
    "update.php", "xmlrpc.php",
])

# Joomla comprehensive
_large_extra.extend([
    "components/com_banners", "components/com_categories",
    "components/com_contact", "components/com_content",
    "components/com_finder", "components/com_installer",
    "components/com_languages", "components/com_media",
    "components/com_messages", "components/com_modules",
    "components/com_newsfeeds", "components/com_plugins",
    "components/com_postinstall", "components/com_redirect",
    "components/com_search", "components/com_menus",
    "components/com_associations", "components/com_cache",
    "components/com_config", "components/com_fields",
    "components/com_tags", "components/com_workflow",
    "administrator/components/com_banners",
    "administrator/components/com_categories",
    "administrator/components/com_contact",
    "administrator/components/com_content",
    "administrator/components/com_finder",
    "administrator/components/com_installer",
    "administrator/components/com_languages",
    "administrator/components/com_media",
    "administrator/components/com_messages",
    "administrator/components/com_modules",
    "administrator/components/com_plugins",
    "administrator/components/com_postinstall",
    "administrator/components/com_redirect",
    "administrator/components/com_search",
    "administrator/components/com_menus",
    "administrator/components/com_associations",
    "administrator/components/com_cache",
    "administrator/components/com_config",
    "administrator/components/com_fields",
    "administrator/components/com_tags",
    "administrator/components/com_workflow",
    "administrator/modules/mod_login",
    "administrator/modules/mod_menu",
    "administrator/modules/mod_quickicon",
    "administrator/modules/mod_status",
    "administrator/modules/mod_toolbar",
    "administrator/templates/isis", "administrator/templates/atum",
    "templates/protostar", "templates/beez3",
    "plugins/authentication/joomla", "plugins/authentication/ldap",
    "plugins/authentication/gmail",
    "plugins/content/joomla", "plugins/content/loadmodule",
    "plugins/content/pagebreak", "plugins/content/vote",
    "plugins/system/cache", "plugins/system/debug",
    "plugins/system/languagefilter", "plugins/system/sef",
    "plugins/system/session", "plugins/system/stats",
    "plugins/system/webauthn",
    "plugins/user/joomla", "plugins/user/profile",
    "installation/", "installation/model",
    "installation/view", "installation/template",
])

# Magento deeper
_large_extra.extend([
    "app/code/core/Mage/Admin", "app/code/core/Mage/Adminhtml",
    "app/code/core/Mage/Catalog", "app/code/core/Mage/Checkout",
    "app/code/core/Mage/Cms", "app/code/core/Mage/Core",
    "app/code/core/Mage/Customer", "app/code/core/Mage/Dataflow",
    "app/code/core/Mage/Directory", "app/code/core/Mage/Eav",
    "app/code/core/Mage/ImportExport", "app/code/core/Mage/Newsletter",
    "app/code/core/Mage/Oauth", "app/code/core/Mage/Paypal",
    "app/code/core/Mage/Sales", "app/code/core/Mage/Shipping",
    "app/code/core/Mage/Sitemap", "app/code/core/Mage/Tag",
    "app/code/core/Mage/Tax", "app/code/core/Mage/Weee",
    "app/code/core/Mage/Wishlist",
    "app/code/community/Phoenix", "app/code/community/Aoe",
    "app/design/adminhtml/default/default",
    "app/design/frontend/default/default",
    "app/design/frontend/base/default",
    "skin/adminhtml/default/default",
    "skin/frontend/default/default",
    "skin/frontend/base/default",
    "js/varien", "js/mage", "js/tiny_mce",
    "lib/Magento", "lib/Varien", "lib/Zend",
    "media/catalog/product", "media/wysiwyg",
    "media/downloadable", "media/customer",
    "var/export", "var/import", "var/report",
    "var/log/exception.log", "var/log/system.log",
    "var/log/payment.log", "var/log/shipping.log",
])

# WebLogic
_large_extra.extend([
    "wls-wsat/CoordinatorPortType",
    "wls-wsat/CoordinatorPortType11",
    "wls-wsat/RegistrationPortTypeRPC",
    "wls-wsat/RegistrationRequesterPortType",
    "wls-wsat/RegistrationRequesterPortType11",
    "_async/AsyncResponseService",
    "_async/AsyncResponseServiceHttps",
    "console/login/LoginForm.jsp",
    "bewls", "uddiexplorer", "uddiexplorer/SearchPublicRegistries.jsp",
    "wls9_async_response/AsyncResponseService",
])

# CI/CD deeper
_large_extra.extend([
    ".github/workflows/ci.yml", ".github/workflows/deploy.yml",
    ".github/workflows/release.yml", ".github/workflows/test.yml",
    ".github/workflows/lint.yml", ".github/workflows/build.yml",
    ".github/dependabot.yml", ".github/CODEOWNERS",
    ".github/FUNDING.yml", ".github/SECURITY.md",
    ".github/CONTRIBUTING.md",
    ".gitlab-ci.yml", ".gitlab-ci-staging.yml",
    ".gitlab-ci-production.yml",
    ".circleci/config.yml",
    "Jenkinsfile", "Jenkinsfile.declarative", "Jenkinsfile.script",
    "azure-pipelines.yml", "azure-pipelines-staging.yml",
    "bitbucket-pipelines.yml",
    ".drone.yml", ".drone.star",
    "cloudbuild.yaml", "buildspec.yml",
    "appveyor.yml", "wercker.yml",
    ".github/actions/build/action.yml",
    ".github/actions/deploy/action.yml",
    ".github/actions/test/action.yml",
])

# Git internals
_large_extra.extend([
    ".git/logs/HEAD", ".git/logs/refs/heads/main",
    ".git/logs/refs/heads/master",
    ".git/logs/refs/heads/develop",
    ".git/logs/refs/heads/production",
    ".git/logs/refs/remotes/origin",
    ".git/logs/refs/remotes/upstream",
    ".git/refs/heads/main", ".git/refs/heads/master",
    ".git/refs/heads/develop", ".git/refs/heads/production",
    ".git/refs/remotes/origin/main",
    ".git/refs/remotes/origin/master",
    ".git/refs/tags/v1", ".git/refs/tags/v2",
    ".git/description", ".git/index",
    ".git/hooks/pre-commit", ".git/hooks/post-commit",
    ".git/hooks/pre-push", ".git/hooks/post-receive",
    ".git/COMMIT_EDITMSG", ".git/packed-refs",
])

# IIS / .NET deeper
_large_extra.extend([
    "aspnet_client/system_web", "aspnet_client/system_web/4_0",
    "App_Data/aspnetdb.mdf", "App_Data/aspnet_request_log",
    "appsettings.Production.json", "appsettings.Staging.json",
    "appsettings.Local.json",
    "web.debug.config", "web.release.config",
    "hostingstart.html", "hostingstart.aspx",
    "error.aspx", "404.aspx", "500.aspx",
    "trace.axd?op=view", "trace.axd?op=clear",
])

# CGI / legacy
_large_extra.extend([
    "cgi-bin/test.cgi", "cgi-bin/test-cgi", "cgi-bin/env.cgi",
    "cgi-bin/printenv", "cgi-bin/shell.cgi",
    "cgi-bin/PHF.cgi", "cgi-bin/Count.cgi",
    "cgi-bin/faxsurvey", "cgi-bin/htmlscript",
    "cgi-bin/nph-test-cgi", "cgi-bin/webdist.cgi",
    "cgi-bin/wrap.cgi", "cgi-bin/AgForm.cgi",
    "scripts/samples/search/query Hits",
])

# Shell backdoors / webshells
_large_extra.extend([
    "shell.php", "cmd.php", "c99.php", "r57.php",
    "webshell.php", "backdoor.php", "hack.php",
    "iron.php", "WSO.php", "FilesMan.php",
    "simple-backdoor.php", "php-reverse-shell.php",
    "b374k.php", "alfa.php", "tarantula.php",
    "weevely.php", "sniper.php",
    "c100.php", "c200.php", "c99-liteshell.php",
    "r57shell.php", "r57i.php", "r57-liteshell.php",
    "Syrian.php", "hf-u.php", "sniper-v.php",
    "angel.php", "angel1337.php",
    "x00-x.php", "x00-xshell.php",
    "b374k-shell.php", "b374k-mini.php",
    "cyberwarrior.php", "cyber.sh.php",
    "db-config.php.bak", "db-backup.php",
    "upload.php", "upload-handler.php", "upload.php5",
    "filemanager/", "filemanager/login",
    "filemanager/connect",
])

# Databases
_large_extra.extend([
    "phpmyadmin/", "phpmyadmin/index.php",
    "phpMyAdmin/", "phpMyAdmin/index.php",
    "phpmyadmin2/", "phpmyadmin3/",
    "pma/", "pma/index.php",
    "myadmin/", "myadmin/index.php",
    "mysql/", "mysql/index.php",
    "dbadmin/", "dbadmin/index.php",
    "adminer.php", "adminer/index.php",
    "adminer/adminer.php",
    "pgadmin/", "pgadmin/index.html",
    "pgadmin4/", "pgadmin4/index.html",
    "rockmongo/", "rockmongo/index.php",
    "mongo-express/", "mongo-express/app.js",
    "dba/", "dba/index.php",
    "phpMyAdmin-4.0/", "phpMyAdmin-4.8/",
    "phpMyAdmin-4.9/", "phpMyAdmin-5.0/",
])

# Misc monitoring deeper
_large_extra.extend([
    "grafana/api/annotations", "grafana/api/search",
    "grafana/api/snapshots", "grafana/api/health",
    "grafana/d/dashboard/db", "grafana/d/dashboard/new",
    "grafana/org", "grafana/org/users",
    "kibana/app/management", "kibana/app/dev_tools",
    "kibana/api/saved_objects/_export",
    "kibana/api/status", "kibana/login",
    "prometheus/api/v1/status/flags",
    "prometheus/api/v1/status/buildinfo",
    "prometheus/api/v1/metadata",
    "prometheus/api/v1/targets/metadata",
    "prometheus/api/v1/targets",
    "consul/v1/operator/raft/configuration",
    "consul/v1/coordinate/nodes",
    "consul/v1/catalog/services",
    "consul/v1/catalog/node",
    "etcd/v2/stats", "etcd/v2/members",
    "etcd/v3/watch", "etcd/v3/lease",
    "vault/v1/sys/health", "vault/v1/sys/seal-status",
    "vault/v1/sys/key-status", "vault/v1/sys/rotate",
    "vault/v1/identity/entity", "vault/v1/identity/group",
    "nexus/service/rest/v1/repositories",
    "nexus/service/rest/v1/search",
    "nexus/service/rest/written-components",
    "nexus/service/rest/v1/staging",
    "artifactory/api/pypi", "artifactory/api/docker",
    "artifactory/api/npm", "artifactory/api/nuget",
    "artifactory/api/gems", "artifactory/api/cargo",
    "sonarqube/api/ce/activity",
    "sonarqube/api/issues/search",
    "sonarqube/api/measures/component",
    "sonarqube/api/components/search",
    "sonarqube/api/qualitygates/project_status",
])

# Kubernetes / cloud
_large_extra.extend([
    "k8s/deployment.yaml", "k8s/service.yaml",
    "k8s/configmap.yaml", "k8s/secret.yaml",
    "k8s/ingress.yaml", "k8s/rbac.yaml",
    "k8s/pod.yaml", "k8s/daemonset.yaml",
    "k8s/statefulset.yaml", "k8s/cronjob.yaml",
    "k8s/hpa.yaml", "k8s/pvc.yaml",
    "manifests/", "manifests/deployment.yaml",
    "manifests/service.yaml", "manifests/namespace.yaml",
    "helm/", "helm/Chart.yaml", "helm/values.yaml",
    "helm/templates/", "helm/charts/",
    "charts/", "deploy/", "deploy/production.yaml",
    "deploy/staging.yaml", "deploy/docker-compose.yaml",
    "infrastructure/", "terraform/", "ansible/",
    "cloudformation/", "pulumi/",
])

# Misc security
_large_extra.extend([
    "security.txt", ".well-known/security.txt",
    "security.txt.bak", "security.txt.old",
    "CHANGELOG", "CHANGELOG.md", "CHANGELOG.txt",
    "CHANGES", "CHANGES.md", "CHANGES.txt",
    "HISTORY", "HISTORY.md", "HISTORY.txt",
    "NEWS", "NEWS.md", "NEWS.txt",
    "RELEASE", "RELEASE.md", "RELEASE.txt",
    "TODO", "TODO.md", "TODO.txt",
    "ROADMAP", "ROADMAP.md",
    "CONTRIBUTING", "CONTRIBUTING.md",
    "CONTRIBUTORS", "CONTRIBUTORS.md",
    "AUTHORS", "AUTHORS.md",
    "CREDITS", "CREDITS.md",
])

# Misc tools
_large_extra.extend([
    "phpcs.xml", "psalm.xml", "phpstan.neon.dist",
    "rector.php", "ecs.php",
    ".php-cs-fixer.php", ".php-cs-fixer.dist.php",
    "phpmd.xml", "phpmd.xml.dist",
    "infection.json", "infection.json.dist",
    "phpunit.xml.dist", "phpunit.xml.bak",
    ".phpunit.result.cache", ".phpunit.xml",
])

# Misc files
_large_extra.extend([
    ".bashrc", ".bash_profile", ".bash_aliases",
    ".profile", ".zshrc", ".zprofile",
    ".tmux.conf", ".vimrc", ".nanorc",
    ".screenrc", ".htgroup", ".htusers",
    ".passwd", ".shadow", ".shadow.bak",
    ".ssh/authorized_keys", ".ssh/id_rsa", ".ssh/id_rsa.pub",
    ".ssh/known_hosts", ".ssh/config",
    ".aws/credentials", ".aws/config",
    ".azure/accessTokens.json", ".azure/azureProfile.json",
    ".kube/config", ".docker/config.json",
    ".npmrc", ".pypirc", ".gem/credentials",
    ".netrc", ".ftpconfig", ".sftp.json",
])

_large_extra.extend([
    "readme.md", "README.md.bak", "LICENSE.md",
    "CONTRIBUTING.md", "SECURITY.md",
    "CODE_OF_CONDUCT.md", "CODEOWNERS",
    "NOTICE", "NOTICE.txt", "NOTICE.md",
    "COPYING", "COPYING.txt", "COPYING.md",
    "PATENTS", "PATENTS.txt",
    "VERSION", "VERSION.md",
    "BUILD", "BUILD.md",
    "test/", "tests/", "spec/", "specs/",
    "features/", "examples/", "demo/", "sample/",
    "tmp/", "temp/", "cache/", "logs/",
    "dist/", "build/", "out/", "output/",
    "vendor/", "node_modules/", "bower_components/",
    "packages/", "deps/", "dependencies/",
    "third-party/", "3rdparty/", "extern/",
    "external/", "lib/", "libs/", "library/",
    "include/", "includes/", "inc/",
])

# ═══════════════════════════════════════════════════════════════════════
# Combinatorial expansion to reach target sizes
# ═══════════════════════════════════════════════════════════════════════

# Roots that make sense to combine with suffixes
MEDIA_ROOTS = [
    "admin", "api", "auth", "backup", "backups", "blog", "cache",
    "cgi-bin", "config", "css", "dashboard", "data", "db", "debug",
    "dev", "docs", "download", "downloads", "dump", "email", "export",
    "files", "fonts", "ftp", "help", "home", "images", "img",
    "import", "includes", "internal", "js", "lib", "login", "logs",
    "mail", "manage", "manager", "media", "modules", "old", "packages",
    "panel", "portal", "private", "public", "raw", "release",
    "repo", "report", "reports", "resources", "rest", "rss",
    "scripts", "search", "secret", "secure", "server", "settings",
    "shared", "signin", "signup", "source", "sql", "src", "ssh",
    "staging", "static", "status", "storage", "styles", "support",
    "system", "temp", "tmp", "tools", "update", "upload", "uploads",
    "users", "v1", "v2", "v3", "vendor", "version", "video", "web",
    "wiki", "xml",
]

# Suffixes that make sense after a root (real paths)
SUFFIXES = [
    "backup", "bak", "config", "data", "debug", "download",
    "dump", "export", "help", "home", "import", "info", "list",
    "login", "log", "logout", "manage", "new", "old", "open",
    "ping", "readme", "register", "reset", "result", "search",
    "settings", "setup", "show", "signup", "status", "test",
    "token", "update", "upload", "view", "xml", "json", "yaml",
    "sql", "zip", "tar", "gz", "bak", "old", "save",
    "debug", "trace", "error", "access", "system",
    "admin", "editor", "viewer", "list", "index",
    "create", "delete", "edit", "modify", "save",
]

# Extensions that make sense after a path (real files)
EXTENSIONS = [
    ".php", ".asp", ".aspx", ".jsp", ".cgi", ".pl",
    ".py", ".rb", ".js", ".html", ".htm", ".xml",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".conf", ".config", ".env", ".log", ".sql", ".bak",
    ".old", ".save", ".swp", ".txt", ".md",
]

# Build combinatorial paths for medium (limited subset)
# Use only the most relevant roots × suffixes to target ~3000
MEDIUM_ROOTS = [
    "admin", "api", "backup", "config", "css", "dashboard", "data",
    "debug", "dev", "docs", "download", "files", "images", "img",
    "includes", "internal", "js", "lib", "login", "logs", "mail",
    "manage", "manager", "media", "modules", "old", "private",
    "public", "resources", "scripts", "secret", "settings", "shared",
    "src", "staging", "static", "status", "storage", "system",
    "temp", "tmp", "tools", "update", "upload", "uploads",
    "users", "v1", "v2", "vendor", "web",
]

MEDIUM_SUFFIXES = [
    "backup", "config", "debug", "download", "dump",
    "help", "info", "list", "login", "log",
    "new", "old", "open", "ping", "readme",
    "register", "reset", "result", "search", "settings",
    "setup", "show", "status", "test", "update",
    "upload", "view", "xml", "json",
]

MEDIUM_EXTENSIONS = [
    ".php", ".asp", ".aspx", ".jsp", ".py", ".js",
    ".html", ".xml", ".json", ".yaml", ".bak", ".log", ".sql",
]

for root in MEDIUM_ROOTS:
    for suffix in MEDIUM_SUFFIXES:
        medium.append(f"{root}/{suffix}")
    for ext in MEDIUM_EXTENSIONS:
        medium.append(f"{root}{ext}")

# Add more specific framework paths
FRAMEWORK_PATHS = [
    "vendor/symfony", "vendor/laravel", "vendor/cakephp",
    "vendor/zend", "vendor/yii", "vendor/ci",
    "vendor/codeigniter", "vendor/fuel", "vendor/slim",
    "vendor/lumen", "vendor/twig", "vendor/blade",
    "vendor/doctrine", "vendor/eloquent",
    "src/Controller", "src/Model", "src/Service",
    "src/Entity", "src/Repository", "src/Command",
    "src/Event", "src/Listener", "src/Subscriber",
    "src/Handler", "src/Middleware", "src/Provider",
    "src/Exception", "src/Util", "src/Helper",
    "app/Controller", "app/Model", "app/Service",
    "app/Entity", "app/Repository", "app/Command",
    "app/Handler", "app/Middleware", "app/Provider",
    "app/Exception", "app/Util", "app/Helper",
    "lib/Controller", "lib/Model", "lib/Service",
    "lib/Entity", "lib/Repository",
]

for path in FRAMEWORK_PATHS:
    medium.append(path)

# Add date-based paths (common in logs/backups) — trimmed
YEARS = ["2022", "2023", "2024", "2025", "2026"]
MONTHS = ["01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12"]

for year in YEARS:
    for month in MONTHS:
        medium.append(f"backup/{year}/{month}")
        medium.append(f"logs/{year}/{month}")

# Add number-based paths (real pentest patterns) — trimmed to 1-30
for i in range(1, 31):
    medium.append(f"admin/{i}")
    medium.append(f"page/{i}")
    medium.append(f"post/{i}")
    medium.append(f"item/{i}")
    medium.append(f"product/{i}")
    medium.append(f"user/{i}")

# More specific admin panel paths
ADMIN_VARIANTS = [
    "admin/dashboard", "admin/settings", "admin/users",
    "admin/config", "admin/logs", "admin/reports",
    "admin/backup", "admin/system", "admin/maintenance",
    "admin/security", "admin/firewall", "admin/database",
    "admin/terminal", "admin/console", "admin/shell",
    "admin/cache", "admin/cron", "admin/jobs",
    "admin/metrics", "admin/stats", "admin/analytics",
    "admin/export", "admin/import",
]
medium.extend(ADMIN_VARIANTS)

# More API patterns
API_PATHS = [
    "api/v1/users", "api/v1/projects", "api/v1/settings",
    "api/v1/config", "api/v1/status", "api/v1/health",
    "api/v1/auth/login", "api/v1/auth/logout",
    "api/v1/auth/token", "api/v1/search",
    "api/v2/users", "api/v2/projects", "api/v2/settings",
    "api/v2/config", "api/v2/status", "api/v2/health",
    "api/v2/auth/login", "api/v2/auth/logout",
    "api/internal", "api/admin", "api/debug",
    "api/metrics", "api/webhooks", "api/events",
]
medium.extend(API_PATHS)

# ═══════════════════════════════════════════════════════════════════════
# LARGE — now that medium is complete, snapshot it and merge extras
# ═══════════════════════════════════════════════════════════════════════
large = list(medium)
large.extend(_large_extra)

# Build combinatorial paths for large — use DIFFERENT roots than medium
# Keep small to avoid explosion: ~20 roots × ~20 suffixes = ~400 + extras
LARGE_ONLY_ROOTS = [
    "assets", "cdn", "content", "core", "deploy",
    "dist", "examples", "features", "fixtures", "generated",
    "global", "icons", "install", "jobs",
    "languages", "layout", "local", "markup", "messaging",
    "metadata", "misc", "news", "notifications", "objects",
    "options", "patterns", "plugins", "preview", "processed",
    "queue", "raw", "redirects", "registry", "rendered",
    "requests", "responses", "routes", "runtime", "schemas",
    "secure", "security", "services", "sessions", "shell",
    "site", "sites", "snapshots", "srv", "stream",
    "structure", "styles", "support", "sync", "templates",
    "terms", "text", "themes", "tracking", "ui",
    "updates", "utility", "var", "views",
    "volumes", "widget", "widgets", "workspace",
]

LARGE_ONLY_SUFFIXES = [
    "access", "account", "accounts", "action", "add", "admin",
    "archive", "attachment", "attachments", "auth", "authenticate",
    "base", "binary", "block", "blocks",
    "bulk", "callback", "callbacks", "cancel",
    "capture", "category", "check", "chunk", "class",
    "clear", "close", "cloud", "code", "comment",
    "comments", "community", "compile", "compress",
    "configure", "connect", "connection", "connections", "console",
    "content", "contents", "context", "control", "convert",
    "copy", "count", "create", "criteria",
    "current", "custom", "database", "db",
    "default", "definition", "delete",
    "delivery", "deploy", "deployment", "design", "desktop",
    "details", "diagnostic", "dictionary", "directory", "disable",
    "display", "document", "documents", "downloads",
    "dynamic", "edit", "editor", "element",
    "enable", "encode", "encrypt", "end", "endpoint",
    "engagement", "engine", "enrich", "entry", "error",
    "errors", "event", "events", "exception", "exceptions",
    "execute", "export", "express", "extended", "external",
    "extract", "factor", "fail", "failure", "features",
    "fetch", "field", "fields", "filter", "filters",
    "final", "find", "finder", "finish", "flag",
    "flush", "folder", "folders", "follow", "force",
    "form", "format", "forms", "forum",
    "forums", "frame", "function", "functions",
    "gateway", "generate", "generation", "get", "gist",
    "git", "global", "grant", "group", "groups",
    "handler", "handlers", "has", "header", "headers",
    "hidden", "hide", "history", "hold", "hook",
    "hooks", "host", "hosts", "hourly", "http",
    "https", "icon", "icons", "id", "identify",
    "identity", "image", "images", "incoming", "index",
    "information", "init", "inline", "input", "insert",
    "install", "instance", "instances", "instruction",
    "instructions", "internal", "interval", "invalidate",
    "invite", "item", "items", "job", "jobs",
    "join", "json", "key", "keys", "kill",
    "label", "labels", "language", "languages", "last",
    "latest", "layout", "lead", "leads", "list",
    "lists", "load", "location", "locations",
    "login", "logout", "lost", "mail", "manage",
    "manager", "manual", "map", "mapping", "maps",
    "mark", "marking", "master", "match",
    "matches", "max", "member", "members", "memory",
    "menu", "menus", "message", "messages", "meta",
    "metadata", "method", "methods", "migrate", "migration",
    "migrations", "min", "misc", "missing", "mobile",
    "mode", "model", "models", "module", "modules",
    "monitor", "monitoring", "monthly", "more", "move",
    "multiple", "my", "name",
    "namespace", "new", "next", "node", "nodes",
    "notification", "notifications", "object", "objects",
    "observe", "old", "one", "online", "open",
    "operation", "operations", "operator", "options",
    "order", "org", "organization", "organizations",
    "other", "out", "outgoing", "output", "override",
    "owner", "owners", "page", "pages", "parent",
    "password", "patch", "path",
    "paths", "pattern", "patterns", "pending", "permission",
    "permissions", "person", "personal", "picture", "pictures",
    "ping", "platform", "play", "player", "plugin",
    "plugins", "pool", "pop", "popular", "port",
    "portal", "position", "positions", "possible", "post",
    "preview", "print", "private", "process", "processing",
    "profile", "profiles", "program", "programs", "project",
    "projects", "promote", "promotion", "proof", "properties",
    "property", "protocol", "protocols", "proxy", "public",
    "publish", "put", "query", "queue", "queued",
    "random", "ranking", "rate", "rating", "read",
    "ready", "receipt", "receive", "recent", "recommend",
    "recovery", "recycle", "redirect", "redirects", "reference",
    "references", "refresh", "register", "registration", "reject",
    "relation", "relations", "relationship", "relationships",
    "release", "remove", "rename", "repair", "repeat",
    "report", "reports", "request", "requests", "require",
    "required", "requirement", "requirements", "rerun", "reset",
    "resolution", "resolve", "resource", "resources", "response",
    "responses", "restore", "result", "results", "retry",
    "return", "review", "reviews", "revision", "revisions",
    "right", "rights", "role", "roles", "rollout",
    "root", "rotate", "route", "router", "routes",
    "row", "rule", "rules", "run", "running",
    "runtime", "s3", "safe", "save", "scan",
    "schema", "schemas", "script", "scripts", "search",
    "secure", "security", "seed", "select", "send",
    "sender", "server", "service", "services", "session",
    "sessions", "set", "setting", "settings", "setup",
    "share", "shared", "shutdown", "side", "sign",
    "site", "sites", "sitemap", "snapshot", "snapshots",
    "soft", "some", "sort", "source", "sources",
    "span", "spec", "special", "split", "sql",
    "src", "ssh", "ssl", "standard", "start",
    "state", "statement", "statistics", "stats", "status",
    "stem", "stop", "store", "stores", "strategy",
    "string", "structure", "structures", "style", "styles",
    "submit", "subscribe", "subscription", "subscriptions",
    "success", "suggest", "suggestion", "suggestions",
    "summary", "support", "sure", "switch", "symbol",
    "system", "tag", "tags", "target", "targets",
    "task", "tasks", "team", "teams", "tech",
    "template", "templates", "temporary", "term", "terms",
    "test", "testing", "tests", "text", "theme",
    "themes", "thread", "threads", "ticket", "tickets",
    "token", "tokens", "tool", "tools", "topic",
    "topics", "trace", "tracking", "train", "transfer",
    "transform", "translate", "tree", "trend", "trends",
    "trigger", "triggers", "type", "types", "ui",
    "undo", "unique", "update", "updates", "upload",
    "url", "urls", "usage", "use", "user",
    "users", "utility", "valid", "validate", "validation",
    "value", "values", "variable", "variables", "version",
    "versions", "video", "videos", "view", "viewer",
    "views", "virtual", "visible", "visit", "visual",
    "volume", "volumes", "vote", "votes", "waiting",
    "warning", "warnings", "watch", "webhook",
    "webhooks", "week", "weekly", "weight", "widget",
    "widgets", "wiki", "window", "worker", "workers",
    "workspace", "write", "writer", "xml", "xsd",
    "xsl", "xslt", "yaml", "year", "yearly",
    "yesterday", "zip", "zone", "zoom",
]

# Use top 45 roots × top 65 suffixes + extensions
for root in LARGE_ONLY_ROOTS[:45]:
    for suffix in LARGE_ONLY_SUFFIXES[:65]:
        large.append(f"{root}/{suffix}")

for ext in EXTENSIONS:
    for root in LARGE_ONLY_ROOTS[:35]:
        large.append(f"{root}{ext}")

# More specific framework paths for large
LARGE_FRAMEWORK_PATHS = [
    "app/Http/Controllers", "app/Http/Middleware",
    "app/Models", "app/Providers", "app/Services",
    "app/Repositories", "app/Events", "app/Listeners",
    "app/Jobs", "app/Notifications", "app/Policies",
    "app/Exceptions", "app/Console", "app/Mail",
    "app/Observers", "app/Rules", "app/Casts",
    "app/Traits", "app/Enums", "app/Interfaces",
    "bootstrap/cache", "bootstrap/app.php",
    "config/auth", "config/broadcasting", "config/cache",
    "config/cors", "config/database", "config/filesystems",
    "config/hashing", "config/logging", "config/mail",
    "config/queue", "config/services", "config/session",
    "config/view", "config/app", "config/queue",
    "database/migrations", "database/seeders",
    "database/factories", "database/data",
    "routes/api", "routes/console", "routes/web",
    "public/css", "public/js", "public/img",
    "public/fonts", "public/build", "public/mix-manifest",
    "storage/app/public", "storage/framework/cache",
    "storage/framework/sessions", "storage/framework/views",
    "storage/logs", "resources/views", "resources/js",
    "resources/css", "resources/lang", "resources/sass",
    "resources/assets", "resources/fonts",
]

for path in LARGE_FRAMEWORK_PATHS:
    large.append(path)

# Limited number-based for large (1-50 instead of 1-100)
for i in range(1, 51):
    large.append(f"admin/{i}")
    large.append(f"page/{i}")
    large.append(f"post/{i}")
    large.append(f"item/{i}")
    large.append(f"product/{i}")
    large.append(f"user/{i}")

# Limited date-based for large
for year in ["2023", "2024", "2025", "2026"]:
    for month in ["01", "04", "07", "10"]:
        large.append(f"backup/{year}/{month}")
        large.append(f"logs/{year}/{month}")

# ═══════════════════════════════════════════════════════════════════════
# Write
# ═══════════════════════════════════════════════════════════════════════
sw = write_list(BASE / "small.txt", small)
mw = write_list(BASE / "medium.txt", medium)
lw = write_list(BASE / "large.txt", large)
print(f"small={sw}, medium={mw}, large={lw}")
