import cutter
from PySide2.QtWidgets import QAction


class JIR2StringDecoderPlugin(cutter.CutterPlugin):
    name = "Journey into Radare 2 Part 3 String Decoder"
    description = "String decoder for APT33 Malware from Journey into Radare 2 Part 3"
    version = "1.0"
    author = "Hamled"

    def setupPlugin(self):
        pass

    def setupInterface(self, main):
        action = QAction("JIR2 String Decoder", main)
        action.setCheckable(False)
        action.triggered.connect(self.decodeAll)

        pluginsMenu = main.getMenuByType(main.MenuType.Plugins)
        pluginsMenu.addAction(action)

    def buildDecoderTable(self):
        self.decoder = {
            'addr': 0x41ba3c,
            'len':  0x41ba79 - 0x41ba3c,
            'fcn':  0x4012a0,
        }

        self.decoder['tbl'] = cutter.cmdj("pxj %d @ %d" % (self.decoder['len'], self.decoder['addr']))

    def decode(self, indexes):
        return ''.join([ chr(self.decoder['tbl'][x]) for x in indexes[::2] ])

    def decodeAll(self):
        # Start with analysis
        cutter.cmd('aa')

        # Build the decoder table
        self.buildDecoderTable()

        # Dump all the strings passed to decoder function
        for xref in cutter.cmdj("axtj %d" % self.decoder['fcn']):
            xref_addr = xref['from']
            arg_len, arg_offsets = cutter.cmdj("pdj -2 @ %d" % xref_addr)

            if not 'val' in arg_len:
                continue

            indexes = cutter.cmdj("pxj %d @ %d" % (arg_len['val'] * 2, arg_offsets['val']))
            decoded_str = self.decode(indexes)

            #print("%s @ %s" % (decoded_str, hex(xref_addr)))
            cutter.cmd("CC Decoded: %s @ %d" % (decoded_str, xref_addr))

        # Refresh interface
        cutter.refresh()

def create_cutter_plugin():
    return JIR2StringDecoderPlugin()
