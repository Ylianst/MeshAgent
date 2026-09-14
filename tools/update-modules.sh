#!/bin/sh
# Updates the embedded JS modules with the corresponding files in modules/*.js.
# The file changed (in microscript, ILibDuktape_Polyfills.c or ILibDuktape_EmbeddedModules.c)
# depends on which is used.
# Done through update-modules.js, run in a built agent binary by default or under node with -node.
#
# usage: update-modules.sh [-update | -export[=dir] | -list | -check] [-add=name1,name2] [-remove=name1,name2] [-sync] [-dryrun] [-striplegacy] [-binarypath=path | -node]
#
#   -update           update every embedded module whose modules/<name>.js changed. Leaves entries
#                     whose source file is gone in place, and does not add anything new
#   -add=list         comma-separated module names to update, or add as a new entry when a name is
#                     not embedded yet (each needs a matching modules/<name>.js). On its own it
#                     touches nothing else; with -update or -sync the rest is updated too
#   -remove=list      comma-separated module names to drop from the embedded table, whether or not
#                     modules/<name>.js still exists. Same rule as -add for the other entries
#   -sync             in addition to updating, follow modules/ exactly: add any modules/<name>.js
#                     with no entry yet, and remove entries whose modules/<name>.js is gone.
#   -dryrun           only report what would change.
#   -check            dry run that exits 1 when anything would change, for CI. Combine with -sync
#                     to also fail on a modules/<name>.js that is not embedded yet
#   -export[=dir]     save the currently embedded scripts, decompressed, into the directory
#                     (default modules_expanded/).
#   -list             print the currently embedded module names and sizes.
#   -binarypath=path  the agent to run in. Default is a built Linux agent in the repository root
#   -node             run under a plain 'node' on PATH instead of an agent binary
#   -striplegacy      moves the embedded modules into ILibDuktape_EmbeddedModules.c: cuts the
#                     addCompressedModule() statements out of ILibDuktape_Polyfills.c and adds a
#                     call to ILibDuktape_Polyfills_EmbeddedModules(ctx) instead.
#

cd "$(dirname "$0")/.." || exit 1

if [ $# -eq 0 ]; then
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

AGENT= UPDATE=0 ADD= REMOVE= SYNC=0 DRYRUN=0 CHECK=0 EXPORT= LIST=0 USE_NODE=0 STRIPLEGACY=0
while [ $# -gt 0 ]; do
    case "$1" in
        -update) UPDATE=1 ;;
        -check) CHECK=1 ;;
        -list) LIST=1 ;;
        -sync) SYNC=1 ;;
        -dryrun) DRYRUN=1 ;;
        -striplegacy) STRIPLEGACY=1 ;;
        -node) USE_NODE=1 ;;
        -export) EXPORT=modules_expanded ;;
        -export=*) EXPORT="${1#*=}" ;;
        -add=*) ADD="${1#*=}" ;;
        -remove=*) REMOVE="${1#*=}" ;;
        -binarypath=*) AGENT="${1#*=}" ;;
        -add|-remove|-binarypath)
            if [ $# -lt 2 ]; then echo "$1 needs a value" >&2; exit 1; fi
            case "$1" in
                -add) ADD="$2" ;;
                -remove) REMOVE="$2" ;;
                *) AGENT="$2" ;;
            esac
            shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done

# The settings travel as environment variables rather than as JS source, so no value needs escaping.
# The chdir is for a Windows agent run from Git Bash: it moves to its own directory at startup, a POSIX agent does not.
# Git Bash's 'pwd -W' gives the Windows spelling that agent needs, elsewhere plain pwd is used and the chdir is a no-op.
UPDATE_ROOT=$(pwd -W 2>/dev/null || pwd)
export UPDATE_ROOT UPDATE_UPDATE="$UPDATE" UPDATE_ADD="$ADD" UPDATE_REMOVE="$REMOVE" UPDATE_SYNC="$SYNC" UPDATE_DRYRUN="$DRYRUN" UPDATE_CHECK="$CHECK" UPDATE_EXPORT="$EXPORT" UPDATE_LIST="$LIST" UPDATE_STRIP_LEGACY="$STRIPLEGACY"
SCRIPT="try { process.chdir(process.env.UPDATE_ROOT); } catch (e) { } try { eval(require('fs').readFileSync('tools/update-modules/update-modules.js').toString()); } catch (e) { console.log(e); process.exit(1); } process.exit(UPDATE_EXIT_CODE);"

# Under node, pako is what makes the compressed bytes match the agent's. Offer to install it once, only when someone is there to answer.
run_node() {
    if [ ! -d tools/update-modules/node_modules/pako ] && command -v npm >/dev/null 2>&1 && [ -t 0 ]; then
        printf "pako is not installed under tools/update-modules/, so node's zlib would produce different bytes than the agent. Run 'npm install' there now? [y/N] "
        read -r answer
        case "$answer" in y|Y|yes|YES) (cd tools/update-modules && npm install --no-audit --no-fund) ;; esac
    fi
    echo "Using node"
    exec node -e "$SCRIPT"
}

if [ "$USE_NODE" = "1" ]; then
    [ -n "$AGENT" ] && echo "-node was passed. Ignoring -binarypath $AGENT" >&2
    if ! command -v node >/dev/null 2>&1; then
        echo "-node was passed but node is not on PATH." >&2
        exit 1
    fi
    run_node
fi

if [ -n "$AGENT" ]; then
    if [ ! -f "$AGENT" ] || [ ! -x "$AGENT" ]; then
        echo "-binarypath $AGENT is not an executable file" >&2
        exit 1
    fi
    # A bare file name would be looked up in PATH rather than here, so it needs the './' to stay a path.
    case "$AGENT" in */*) ;; *) AGENT="./$AGENT" ;; esac
else
    for c in meshagent_x86-64 meshagent_x86-64_nokvm meshagent_x86; do
        if [ -x "$c" ]; then AGENT="./$c"; break; fi
    done
    if [ -z "$AGENT" ]; then
        if command -v node >/dev/null 2>&1; then
            echo "No agent binary found in the repository root. Falling back to node."
            run_node
        fi
        echo "No agent binary found in the repository root, and node is not on PATH. Build one first (make linux ARCHID=6), or pass one with -binarypath." >&2
        exit 1
    fi
fi

if ! command -v base64 >/dev/null 2>&1; then
    echo "base64 is not on PATH, needed to pass the script via -b64exec." >&2
    exit 1
fi

#circumvent 4096 character limit pre-#376 fix
SCRIPT_B64=$(printf '%s' "$SCRIPT" | base64 | tr -d '\n')

echo "Using agent: $AGENT"
exec "$AGENT" -b64exec "$SCRIPT_B64"
