#!/bin/bash
#Author: Loris Zigliani | https://github.com/loriszigliani

CONFIG_DIR="/etc/wireguard"

function list_interfaces {
    ls $CONFIG_DIR/*.conf 2>/dev/null | xargs -n 1 basename | sed 's/\.conf$//'
}

function show_main_menu {
    clear
    echo "-----------------------------"
    echo "WireGuard Configuration Menu"
    echo "-----------------------------"
    echo "1. Select Interface"
    echo "2. Add New Interface"
    echo "3. Exit"
    echo "-----------------------------"
}

function show_interface_menu {
    clear
    echo "-----------------------------"
    echo "Managing Interface: $SELECTED_INTERFACE"
    echo "-----------------------------"
    echo "1. Modify Configuration"
    echo "2. Delete Configuration"
    echo "3. Enable Interface at Startup"
    echo "4. Disable Interface at Startup"
    echo "5. Back to Main Menu"
    echo "-----------------------------"
}

function add_interface {
    clear
    read -p "Enter new interface name: " interface_name
    config_path="$CONFIG_DIR/$interface_name.conf"
    if [ -f "$config_path" ]; then
        echo "Configuration for $interface_name already exists."
        read -p "Press enter to continue..."
        return
    fi

    private_key=$(wg genkey)
    public_key=$(echo $private_key | wg pubkey)

    cat <<EOL > "$config_path"
[Interface]
PrivateKey = $private_key
Address = <ip-address>
ListenPort = <port>
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
EOL
    echo "Configuration for $interface_name created at $config_path. Please edit the file to add the correct details."
    read -p "Press enter to continue..."
}

function modify_interface {
    wg-quick down $SELECTED_INTERFACE
    nano "$CONFIG_DIR/$SELECTED_INTERFACE.conf"
    wg-quick up $SELECTED_INTERFACE
    echo "Configuration for $SELECTED_INTERFACE reloaded."
    read -p "Press enter to continue..."
}

function delete_interface {
    config_path="$CONFIG_DIR/$SELECTED_INTERFACE.conf"
    if [ -f "$config_path" ]; then
        systemctl stop wg-quick@$SELECTED_INTERFACE
        systemctl disable wg-quick@$SELECTED_INTERFACE
        rm -f "$config_path"
        echo "Configuration and startup service for $SELECTED_INTERFACE deleted."
    else
        echo "Configuration for $SELECTED_INTERFACE does not exist."
    fi
    read -p "Press enter to continue..."
}

function enable_at_startup {
    config_path="$CONFIG_DIR/$SELECTED_INTERFACE.conf"
    if [ -f "$config_path" ]; then
        systemctl enable wg-quick@$SELECTED_INTERFACE
        systemctl start wg-quick@$SELECTED_INTERFACE
        echo "Interface $SELECTED_INTERFACE enabled at startup and started."
    else
        echo "Configuration for $SELECTED_INTERFACE does not exist."
    fi
    read -p "Press enter to continue..."
}

function disable_at_startup {
    config_path="$CONFIG_DIR/$SELECTED_INTERFACE.conf"
    if [ -f "$config_path" ]; then
        systemctl stop wg-quick@$SELECTED_INTERFACE
        systemctl disable wg-quick@$SELECTED_INTERFACE
        echo "Interface $SELECTED_INTERFACE disabled at startup and stopped."
    else
        echo "Configuration for $SELECTED_INTERFACE does not exist."
    fi
    read -p "Press enter to continue..."
}

while true; do
    show_main_menu
    read -p "Choose an option: " main_choice
    case $main_choice in
        1)
            INTERFACES=($(list_interfaces))
            if [ ${#INTERFACES[@]} -eq 0 ]; then
                echo "No interfaces found."
                read -p "Press enter to continue..."
                continue
            fi
            echo "Available interfaces:"
            for i in "${!INTERFACES[@]}"; do
                echo "$((i + 1)). ${INTERFACES[$i]}"
            done
            read -p "Select an interface (number): " interface_choice
            if [ $interface_choice -ge 1 ] && [ $interface_choice -le ${#INTERFACES[@]} ]; then
                SELECTED_INTERFACE=${INTERFACES[$((interface_choice - 1))]}
            else
                echo "Invalid choice. Please try again."
                read -p "Press enter to continue..."
                continue
            fi

            while true; do
                show_interface_menu
                read -p "Choose an option: " interface_choice
                case $interface_choice in
                    1) modify_interface ;;
                    2) delete_interface ; break ;;
                    3) enable_at_startup ;;
                    4) disable_at_startup ;;
                    5) break ;;
                    *) echo "Invalid choice. Please try again." ;;
                esac
                echo ""
            done
            ;;
        2) add_interface ;;
        3) exit 0 ;;
        *) echo "Invalid choice. Please try again." ;;
    esac
    echo ""
done
