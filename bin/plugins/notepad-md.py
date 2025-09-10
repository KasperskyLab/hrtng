"""
 This plugin renders markdown content of "IDA notepad" in a docked viewer
 Run and refresh it with "Ctrl-Shift-F7" hotkey
 The plugin is a part of hrtng project (https://github.com/KasperskyLab/hrtng)

 Thanks Alexander Hanel for msdocviewer plugin is used as example of markdown viewer implementation
"""

import ida_kernwin
import ida_nalt
import ida_idaapi

from idaapi import PluginForm
# swap commented out PyQt5 to PySide6 in lines below for IDA < 9.2
#from PyQt5 import QtWidgets
from PySide6 import QtWidgets

mdnpForm = None

class mdnp(ida_kernwin.PluginForm):
  def OnCreate(self, form):
    self.lbl = QtWidgets.QLabel()
    self.lbl.setText("markdown-view")
    self.view = QtWidgets.QTextEdit()
    self.view.setReadOnly(True)
    self.layout = QtWidgets.QVBoxLayout()
    self.layout.addWidget(self.view)
    self.parent = self.FormToPyQtWidget(form)
    self.parent.setLayout(self.layout)
    self.loadText()

  def loadText(self):
    text = ida_nalt.get_ida_notepad_text()
    self.view.setMarkdown(text)

  def OnClose(self, form):
    global mdnpForm
    del mdnpForm
    mdnpForm = None

class mdnpPlugin(ida_idaapi.plugin_t):
  flags = ida_idaapi.PLUGIN_MOD
  comment = "view notepad text as markdown"
  help = ""
  wanted_name = "[hrt] markdown notepad"
  wanted_hotkey = "Ctrl-Shift-F7"

  def init(self):
    return ida_idaapi.PLUGIN_KEEP

  def run(self, arg):
    global mdnpForm
    if not mdnpForm:
      mdnpForm = mdnp()
      mdnpForm.Show("markdown-view", options=(ida_kernwin.PluginForm.WOPN_PERSIST | ida_kernwin.PluginForm.WCLS_CLOSE_LATER))
      ida_kernwin.open_notepad_window()
      ida_kernwin.set_dock_pos("markdown-view", "Database notepad", ida_kernwin.DP_RIGHT)
    else:
      mdnpForm.loadText()

  def term(self):
    pass

# -----------------------------------------------------------------------
def PLUGIN_ENTRY():
  return mdnpPlugin()
