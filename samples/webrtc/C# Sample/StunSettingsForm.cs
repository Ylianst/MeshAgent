using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace WebRTC_Sample
{
    public partial class StunSettingsForm : Form
    {
        public StunSettingsForm()
        {
            InitializeComponent();
        }

        public Boolean StunServersInUse
        {
            get { return stunCheckBox.Checked; }
            set { stunTextBox.Enabled = stunCheckBox.Checked = value; }
        }

        public String[] StunServers
        {
            get { return stunTextBox.Text.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries); }
            set { stunTextBox.Text = string.Join("\r\n", value); }
        }

        private void okButton_Click(object sender, EventArgs e)
        {
            DialogResult = System.Windows.Forms.DialogResult.OK;
        }

        private void cancelButton_Click(object sender, EventArgs e)
        {
            DialogResult = System.Windows.Forms.DialogResult.Cancel;
        }

        private void stunCheckBox_CheckedChanged(object sender, EventArgs e)
        {
            stunTextBox.Enabled = stunCheckBox.Checked;
        }
    }
}
