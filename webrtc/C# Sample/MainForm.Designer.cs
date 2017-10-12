namespace WebRTC_Sample
{
    partial class MainForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(MainForm));
            this.launchBrowserButton = new System.Windows.Forms.Button();
            this.label1 = new System.Windows.Forms.Label();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.serverLinkLabel_passive = new System.Windows.Forms.LinkLabel();
            this.label4 = new System.Windows.Forms.Label();
            this.stunSettingsButton = new System.Windows.Forms.Button();
            this.stunLabel = new System.Windows.Forms.Label();
            this.label3 = new System.Windows.Forms.Label();
            this.serverStatusLabel = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.serverLinkLabel = new System.Windows.Forms.LinkLabel();
            this.closeButton = new System.Windows.Forms.Button();
            this.infoLinkLabel = new System.Windows.Forms.LinkLabel();
            this.menuStrip1 = new System.Windows.Forms.MenuStrip();
            this.fileToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.closeToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.settingsToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.sTUNServersToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.pictureBox1 = new System.Windows.Forms.PictureBox();
            this.groupBox1.SuspendLayout();
            this.menuStrip1.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).BeginInit();
            this.SuspendLayout();
            // 
            // launchBrowserButton
            // 
            this.launchBrowserButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.launchBrowserButton.Location = new System.Drawing.Point(423, 170);
            this.launchBrowserButton.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.launchBrowserButton.Name = "launchBrowserButton";
            this.launchBrowserButton.Size = new System.Drawing.Size(131, 41);
            this.launchBrowserButton.TabIndex = 2;
            this.launchBrowserButton.Text = "New Instance";
            this.launchBrowserButton.UseVisualStyleBackColor = true;
            this.launchBrowserButton.Click += new System.EventHandler(this.browserButton_Click);
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(11, 49);
            this.label1.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(145, 17);
            this.label1.TabIndex = 3;
            this.label1.Text = "Browser-Initiated URL";
            // 
            // groupBox1
            // 
            this.groupBox1.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.groupBox1.Controls.Add(this.serverLinkLabel_passive);
            this.groupBox1.Controls.Add(this.label4);
            this.groupBox1.Controls.Add(this.stunSettingsButton);
            this.groupBox1.Controls.Add(this.stunLabel);
            this.groupBox1.Controls.Add(this.label3);
            this.groupBox1.Controls.Add(this.serverStatusLabel);
            this.groupBox1.Controls.Add(this.label2);
            this.groupBox1.Controls.Add(this.serverLinkLabel);
            this.groupBox1.Controls.Add(this.label1);
            this.groupBox1.Location = new System.Drawing.Point(109, 33);
            this.groupBox1.Margin = new System.Windows.Forms.Padding(4);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Padding = new System.Windows.Forms.Padding(4);
            this.groupBox1.Size = new System.Drawing.Size(444, 121);
            this.groupBox1.TabIndex = 4;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "State";
            // 
            // serverLinkLabel_passive
            // 
            this.serverLinkLabel_passive.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.serverLinkLabel_passive.Location = new System.Drawing.Point(175, 70);
            this.serverLinkLabel_passive.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.serverLinkLabel_passive.Name = "serverLinkLabel_passive";
            this.serverLinkLabel_passive.Size = new System.Drawing.Size(258, 17);
            this.serverLinkLabel_passive.TabIndex = 16;
            this.serverLinkLabel_passive.TextAlign = System.Drawing.ContentAlignment.TopRight;
            this.serverLinkLabel_passive.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.serverLinkLabel_passive_LinkClicked);
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(11, 70);
            this.label4.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(163, 17);
            this.label4.TabIndex = 15;
            this.label4.Text = "Application-Initiated URL";
            // 
            // stunSettingsButton
            // 
            this.stunSettingsButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.stunSettingsButton.Location = new System.Drawing.Point(403, 92);
            this.stunSettingsButton.Margin = new System.Windows.Forms.Padding(4);
            this.stunSettingsButton.Name = "stunSettingsButton";
            this.stunSettingsButton.Size = new System.Drawing.Size(31, 16);
            this.stunSettingsButton.TabIndex = 14;
            this.stunSettingsButton.Text = "*";
            this.stunSettingsButton.UseVisualStyleBackColor = true;
            this.stunSettingsButton.Click += new System.EventHandler(this.stunSettingsButton_Click);
            // 
            // stunLabel
            // 
            this.stunLabel.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.stunLabel.Location = new System.Drawing.Point(137, 92);
            this.stunLabel.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.stunLabel.Name = "stunLabel";
            this.stunLabel.Size = new System.Drawing.Size(257, 16);
            this.stunLabel.TabIndex = 13;
            this.stunLabel.Text = "Disabled";
            this.stunLabel.TextAlign = System.Drawing.ContentAlignment.TopRight;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(11, 92);
            this.label3.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(97, 17);
            this.label3.TabIndex = 8;
            this.label3.Text = "STUN servers";
            // 
            // serverStatusLabel
            // 
            this.serverStatusLabel.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.serverStatusLabel.Location = new System.Drawing.Point(137, 25);
            this.serverStatusLabel.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.serverStatusLabel.Name = "serverStatusLabel";
            this.serverStatusLabel.Size = new System.Drawing.Size(296, 16);
            this.serverStatusLabel.TabIndex = 7;
            this.serverStatusLabel.TextAlign = System.Drawing.ContentAlignment.TopRight;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(11, 25);
            this.label2.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(94, 17);
            this.label2.TabIndex = 5;
            this.label2.Text = "Server Status";
            // 
            // serverLinkLabel
            // 
            this.serverLinkLabel.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.serverLinkLabel.Location = new System.Drawing.Point(172, 49);
            this.serverLinkLabel.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.serverLinkLabel.Name = "serverLinkLabel";
            this.serverLinkLabel.Size = new System.Drawing.Size(261, 17);
            this.serverLinkLabel.TabIndex = 4;
            this.serverLinkLabel.TextAlign = System.Drawing.ContentAlignment.TopRight;
            this.serverLinkLabel.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.serverLinkLabel_LinkClicked);
            // 
            // closeButton
            // 
            this.closeButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.closeButton.DialogResult = System.Windows.Forms.DialogResult.Cancel;
            this.closeButton.Location = new System.Drawing.Point(287, 170);
            this.closeButton.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.closeButton.Name = "closeButton";
            this.closeButton.Size = new System.Drawing.Size(131, 41);
            this.closeButton.TabIndex = 6;
            this.closeButton.Text = "Close";
            this.closeButton.UseVisualStyleBackColor = true;
            this.closeButton.Click += new System.EventHandler(this.closeButton_Click);
            // 
            // infoLinkLabel
            // 
            this.infoLinkLabel.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.infoLinkLabel.Location = new System.Drawing.Point(9, 188);
            this.infoLinkLabel.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.infoLinkLabel.Name = "infoLinkLabel";
            this.infoLinkLabel.Size = new System.Drawing.Size(204, 16);
            this.infoLinkLabel.TabIndex = 9;
            this.infoLinkLabel.TabStop = true;
            this.infoLinkLabel.Text = "info.meshcentral.com";
            this.infoLinkLabel.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.infoLinkLabel_LinkClicked);
            // 
            // menuStrip1
            // 
            this.menuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.fileToolStripMenuItem,
            this.settingsToolStripMenuItem});
            this.menuStrip1.Location = new System.Drawing.Point(0, 0);
            this.menuStrip1.Name = "menuStrip1";
            this.menuStrip1.Padding = new System.Windows.Forms.Padding(8, 2, 0, 2);
            this.menuStrip1.Size = new System.Drawing.Size(569, 36);
            this.menuStrip1.TabIndex = 12;
            this.menuStrip1.Text = "menuStrip1";
            // 
            // fileToolStripMenuItem
            // 
            this.fileToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.closeToolStripMenuItem});
            this.fileToolStripMenuItem.Name = "fileToolStripMenuItem";
            this.fileToolStripMenuItem.Size = new System.Drawing.Size(54, 32);
            this.fileToolStripMenuItem.Text = "&File";
            // 
            // closeToolStripMenuItem
            // 
            this.closeToolStripMenuItem.Name = "closeToolStripMenuItem";
            this.closeToolStripMenuItem.Size = new System.Drawing.Size(152, 32);
            this.closeToolStripMenuItem.Text = "&Close";
            // 
            // settingsToolStripMenuItem
            // 
            this.settingsToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.sTUNServersToolStripMenuItem});
            this.settingsToolStripMenuItem.Name = "settingsToolStripMenuItem";
            this.settingsToolStripMenuItem.Size = new System.Drawing.Size(95, 32);
            this.settingsToolStripMenuItem.Text = "&Settings";
            // 
            // sTUNServersToolStripMenuItem
            // 
            this.sTUNServersToolStripMenuItem.Name = "sTUNServersToolStripMenuItem";
            this.sTUNServersToolStripMenuItem.Size = new System.Drawing.Size(211, 32);
            this.sTUNServersToolStripMenuItem.Text = "STUN servers...";
            this.sTUNServersToolStripMenuItem.Click += new System.EventHandler(this.stunSettingsButton_Click);
            // 
            // pictureBox1
            // 
            this.pictureBox1.Image = global::WebRTC_Sample.Properties.Resources.WebRTCSample;
            this.pictureBox1.Location = new System.Drawing.Point(16, 33);
            this.pictureBox1.Margin = new System.Windows.Forms.Padding(4);
            this.pictureBox1.Name = "pictureBox1";
            this.pictureBox1.Size = new System.Drawing.Size(85, 79);
            this.pictureBox1.TabIndex = 5;
            this.pictureBox1.TabStop = false;
            // 
            // MainForm
            // 
            this.AcceptButton = this.launchBrowserButton;
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.CancelButton = this.closeButton;
            this.ClientSize = new System.Drawing.Size(569, 215);
            this.Controls.Add(this.infoLinkLabel);
            this.Controls.Add(this.closeButton);
            this.Controls.Add(this.pictureBox1);
            this.Controls.Add(this.groupBox1);
            this.Controls.Add(this.launchBrowserButton);
            this.Controls.Add(this.menuStrip1);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MainMenuStrip = this.menuStrip1;
            this.Margin = new System.Windows.Forms.Padding(3, 2, 3, 2);
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "MainForm";
            this.Text = "Meshcentral - WebRTC Sample Server";
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.MainForm_FormClosing);
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.menuStrip1.ResumeLayout(false);
            this.menuStrip1.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button launchBrowserButton;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.Label serverStatusLabel;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.LinkLabel serverLinkLabel;
        private System.Windows.Forms.PictureBox pictureBox1;
        private System.Windows.Forms.Button closeButton;
        private System.Windows.Forms.LinkLabel infoLinkLabel;
        private System.Windows.Forms.MenuStrip menuStrip1;
        private System.Windows.Forms.ToolStripMenuItem fileToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem closeToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem settingsToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem sTUNServersToolStripMenuItem;
        private System.Windows.Forms.Label stunLabel;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.Button stunSettingsButton;
        private System.Windows.Forms.LinkLabel serverLinkLabel_passive;
        private System.Windows.Forms.Label label4;
    }
}

