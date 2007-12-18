
# Check for bash                                                                
[ -z "$BASH_VERSION" ] && return

####################################################################################################

__polkit_auth() {
    local IFS=$'\n'
    local cur="${COMP_WORDS[COMP_CWORD]}"

    case $COMP_CWORD in
        1)
            COMPREPLY=($(IFS=: compgen -S' ' -W "--obtain:--show-obtainable:--explicit:--explicit-detail:--grant:--block:--revoke:--user:--version:--help" -- $cur))
            ;;
        2)
	    case "${COMP_WORDS[1]}" in
                --obtain)   
                    COMPREPLY=($(compgen -W "$(polkit-auth --show-obtainable)" -- $cur))
                    ;;
                --revoke) 
                    COMPREPLY=($(compgen -W "$(polkit-auth --explicit)" -- $cur))
                    ;;
                --grant|--block)
                    COMPREPLY=($(compgen -W "$(polkit-action)" -- $cur))
                    ;;
                --user)   
                    COMPREPLY=($(compgen -u -- $cur))
                    ;;
            esac
            ;;
        3)
	    case "${COMP_WORDS[1]}" in
                --user)
                    COMPREPLY=($(IFS=: compgen -S' ' -W "--explicit:--explicit-detail:--grant:--block:--revoke" -- $cur))
                    ;;
                --grant|--block)
                    COMPREPLY=($(IFS=: compgen -S' ' -W "--constraint" -- $cur))
                    ;;
            esac
            ;;
        4)
	    case "${COMP_WORDS[3]}" in
                --revoke) 
	            case "${COMP_WORDS[1]}" in
                        --user)
                            local afou
                            # we may not be authorized to read the explicit auths for the given user..
                            afou=$(polkit-auth --user ${COMP_WORDS[2]} --explicit 2> /dev/null) 
                            if [ $? != 0 ] ; then
                                # .. so if that fails, fall back to showing all actions
                                afou=$(polkit-action)
                            fi
                            COMPREPLY=($(compgen -W "$afou" -- $cur))
                            ;;
                        *)
                            COMPREPLY=($(compgen -W "$(polkit-action)" -- $cur))
                            ;;
                    esac
                    ;;
                --grant|--block)
                    COMPREPLY=($(compgen -W "$(polkit-action)" -- $cur))
                    ;;
                --constraint)
                    COMPREPLY=($(IFS=: compgen -S' ' -W "local:active:exe\::selinux_context\:" -- $cur))
                    ;;
            esac
            ;;
        5)
	    case "${COMP_WORDS[3]}" in
                --grant|--block)
                    COMPREPLY=($(IFS=: compgen -S' ' -W "--constraint" -- $cur))
                    ;;
            esac
	    case "${COMP_WORDS[1]}" in
                --grant|--block)
                    COMPREPLY=($(IFS=: compgen -S' ' -W "--constraint" -- $cur))
                    ;;
            esac
            ;;
        *)
	    case "${COMP_WORDS[$(($COMP_CWORD - 1))]}" in
                --constraint)
                    COMPREPLY=($(IFS=: compgen -S' ' -W "local:active:exe\::selinux_context\:" -- $cur))
                    ;;
                *)
                    COMPREPLY=($(IFS=: compgen -S' ' -W "--constraint" -- $cur))
                    ;;
            esac
            ;;
    esac
}

####################################################################################################

__polkit_action() {
    local IFS=$'\n'
    local cur="${COMP_WORDS[COMP_CWORD]}"

    case $COMP_CWORD in
        1)
            COMPREPLY=($(IFS=: compgen -S' ' -W "--action:--reset-defaults:--set-defaults-any:--set-defaults-inactive:--set-defaults-active:--show-overrides:--version:--help" -- $cur))
            ;;
        2)
	    case "${COMP_WORDS[1]}" in
                --action|--set-defaults-any|--set-defaults-inactive|--set-defaults-active) 
                    COMPREPLY=($(compgen -W "$(polkit-action)" -- $cur))
                    ;;
                --reset-defaults) 
                    COMPREPLY=($(compgen -W "$(polkit-action --show-overrides)" -- $cur))
                    ;;
            esac
            ;;
        3)
	    case "${COMP_WORDS[1]}" in
                --set-defaults-any|--set-defaults-inactive|--set-defaults-active)
                    COMPREPLY=($(IFS=: compgen -S' ' -W "yes:no:auth_admin_one_shot:auth_admin:auth_admin_keep_session:auth_admin_keep_always:auth_self_one_shot:auth_self:auth_self_keep_session:auth_self_keep_always" -- $cur))
                    ;;
            esac
    esac
}

####################################################################################################

complete -o nospace -F __polkit_auth polkit-auth
complete -o nospace -F __polkit_action polkit-action
