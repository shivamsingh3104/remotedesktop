#!/bin/bash
# Myamoto API - Setup on connect.myamoto.com
# Upload this file + mesh-api-routes.cjs + .env to your meshcentral directory, then:
# chmod +x setup-connect.sh && ./setup-connect.sh

set -e

# Find meshcentral directory
MC_DIR=""
for d in /opt/meshcentral /root/meshcentral /home/meshcentral /usr/local/lib/node_modules/meshcentral ./node_modules/meshcentral; do
  if [ -f "$d/webserver.js" ]; then
    MC_DIR="$d"
    break
  fi
done

if [ -z "$MC_DIR" ]; then
  echo "MeshCentral not found! Searching..."
  MC_DIR=$(find / -name "webserver.js" -path "*/meshcentral/*" 2>/dev/null | head -1 | xargs dirname)
fi

if [ -z "$MC_DIR" ]; then
  echo "ERROR: Cannot find MeshCentral webserver.js"
  echo "Please enter the path to meshcentral folder:"
  read MC_DIR
fi

echo "Found MeshCentral at: $MC_DIR"

# Copy routes file
cp mesh-api-routes.cjs "$MC_DIR/../mesh-api-routes.cjs" 2>/dev/null || cp mesh-api-routes.cjs "$MC_DIR/../../mesh-api-routes.cjs" 2>/dev/null || echo "Warning: mesh-api-routes.cjs copy failed, check path"

# Install required packages
cd "$MC_DIR"
npm install bcryptjs jsonwebtoken crypto-js mssql dotenv

# Patch webserver.js if not already patched
if ! grep -q "Myamoto API Routes" "$MC_DIR/webserver.js"; then
  sed -i '' 's/    return obj;/    \/\/ Myamoto API Routes\n    try {\n        const apiRoutesPath = obj.path.join(__dirname, '"'..\/..\/mesh-api-routes.cjs'"');\n        if (obj.fs.existsSync(apiRoutesPath)) {\n            const addApiRoutes = require(apiRoutesPath);\n            addApiRoutes(obj.app);\n        }\n    } catch (ex) { console.log('"'"'[API] Failed to load routes:'"'"', ex.message); }\n\n    return obj;/' "$MC_DIR/webserver.js" 2>/dev/null || {
    echo "Manual patch needed. Add this before 'return obj;' in $MC_DIR/webserver.js:"
    echo ""
    echo '    // Myamoto API Routes'
    echo '    try {'
    echo "        const apiRoutesPath = obj.path.join(__dirname, '../../mesh-api-routes.cjs');"
    echo '        if (obj.fs.existsSync(apiRoutesPath)) {'
    echo '            const addApiRoutes = require(apiRoutesPath);'
    echo '            addApiRoutes(obj.app);'
    echo '        }'
    echo "    } catch (ex) { console.log('[API] Failed to load routes:', ex.message); }"
  }
  echo "webserver.js patched!"
else
  echo "webserver.js already patched."
fi

# Restart MeshCentral
echo "Restarting MeshCentral..."
pkill -f "meshcentral" 2>/dev/null || true
sleep 2
# Start it again (adjust the start command as needed)
nohup node meshcentral.js > meshcentral.log 2>&1 &
echo "MeshCentral restarted! Check: tail -f meshcentral.log"
echo ""
echo "Done! API is now available at https://connect.myamoto.com/api/auth/login"
