namespace WebRTC_Sample
{
    partial class DebugForm
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
            this.sendRateLabel = new System.Windows.Forms.Label();
            this.retryLabel = new System.Windows.Forms.Label();
            this.normalRetryLabel = new System.Windows.Forms.Label();
            this.rCreditsLabel = new System.Windows.Forms.Label();
            this.windowSizeLabel = new System.Windows.Forms.Label();
            this.fastRecoveryLabel = new System.Windows.Forms.Label();
            this.t3Label = new System.Windows.Forms.Label();
            this.rttLabel = new System.Windows.Forms.Label();
            this.tsnLabel = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // sendRateLabel
            // 
            this.sendRateLabel.AutoSize = true;
            this.sendRateLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 19.8F, ((System.Drawing.FontStyle)((System.Drawing.FontStyle.Bold | System.Drawing.FontStyle.Italic))), System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.sendRateLabel.Location = new System.Drawing.Point(27, 9);
            this.sendRateLabel.Name = "sendRateLabel";
            this.sendRateLabel.Size = new System.Drawing.Size(190, 38);
            this.sendRateLabel.TabIndex = 0;
            this.sendRateLabel.Text = "Send Rate:";
            this.sendRateLabel.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // retryLabel
            // 
            this.retryLabel.AutoSize = true;
            this.retryLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 19.8F, ((System.Drawing.FontStyle)((System.Drawing.FontStyle.Bold | System.Drawing.FontStyle.Italic))), System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.retryLabel.ForeColor = System.Drawing.Color.DarkRed;
            this.retryLabel.Location = new System.Drawing.Point(27, 47);
            this.retryLabel.Name = "retryLabel";
            this.retryLabel.Size = new System.Drawing.Size(272, 38);
            this.retryLabel.TabIndex = 1;
            this.retryLabel.Text = "Fast Retry Rate:";
            this.retryLabel.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // normalRetryLabel
            // 
            this.normalRetryLabel.AutoSize = true;
            this.normalRetryLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 19.8F, ((System.Drawing.FontStyle)((System.Drawing.FontStyle.Bold | System.Drawing.FontStyle.Italic))), System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.normalRetryLabel.Location = new System.Drawing.Point(27, 85);
            this.normalRetryLabel.Name = "normalRetryLabel";
            this.normalRetryLabel.Size = new System.Drawing.Size(315, 38);
            this.normalRetryLabel.TabIndex = 2;
            this.normalRetryLabel.Text = "Normal Retry Rate:";
            this.normalRetryLabel.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // rCreditsLabel
            // 
            this.rCreditsLabel.AutoSize = true;
            this.rCreditsLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 13.8F, ((System.Drawing.FontStyle)((System.Drawing.FontStyle.Bold | System.Drawing.FontStyle.Italic))), System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.rCreditsLabel.Location = new System.Drawing.Point(29, 429);
            this.rCreditsLabel.Name = "rCreditsLabel";
            this.rCreditsLabel.Size = new System.Drawing.Size(215, 29);
            this.rCreditsLabel.TabIndex = 3;
            this.rCreditsLabel.Text = "Receiver Credits:";
            this.rCreditsLabel.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // windowSizeLabel
            // 
            this.windowSizeLabel.AutoSize = true;
            this.windowSizeLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 13.8F, ((System.Drawing.FontStyle)((System.Drawing.FontStyle.Bold | System.Drawing.FontStyle.Italic))), System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.windowSizeLabel.Location = new System.Drawing.Point(29, 400);
            this.windowSizeLabel.Name = "windowSizeLabel";
            this.windowSizeLabel.Size = new System.Drawing.Size(311, 29);
            this.windowSizeLabel.TabIndex = 4;
            this.windowSizeLabel.Text = "Congestion Window Size:";
            this.windowSizeLabel.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // fastRecoveryLabel
            // 
            this.fastRecoveryLabel.AutoSize = true;
            this.fastRecoveryLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 13.8F, ((System.Drawing.FontStyle)((System.Drawing.FontStyle.Bold | System.Drawing.FontStyle.Italic))), System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.fastRecoveryLabel.Location = new System.Drawing.Point(29, 371);
            this.fastRecoveryLabel.Name = "fastRecoveryLabel";
            this.fastRecoveryLabel.Size = new System.Drawing.Size(259, 29);
            this.fastRecoveryLabel.TabIndex = 5;
            this.fastRecoveryLabel.Text = "Fast Recovery Mode:";
            this.fastRecoveryLabel.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // t3Label
            // 
            this.t3Label.AutoSize = true;
            this.t3Label.Font = new System.Drawing.Font("Microsoft Sans Serif", 13.8F, ((System.Drawing.FontStyle)((System.Drawing.FontStyle.Bold | System.Drawing.FontStyle.Italic))), System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.t3Label.Location = new System.Drawing.Point(29, 342);
            this.t3Label.Name = "t3Label";
            this.t3Label.Size = new System.Drawing.Size(189, 29);
            this.t3Label.TabIndex = 6;
            this.t3Label.Text = "T3-RTX Timer:";
            this.t3Label.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // rttLabel
            // 
            this.rttLabel.AutoSize = true;
            this.rttLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 13.8F, ((System.Drawing.FontStyle)((System.Drawing.FontStyle.Bold | System.Drawing.FontStyle.Italic))), System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.rttLabel.Location = new System.Drawing.Point(29, 313);
            this.rttLabel.Name = "rttLabel";
            this.rttLabel.Size = new System.Drawing.Size(218, 29);
            this.rttLabel.TabIndex = 7;
            this.rttLabel.Text = "Round Trip Time:";
            this.rttLabel.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // tsnLabel
            // 
            this.tsnLabel.AutoSize = true;
            this.tsnLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 13.8F, ((System.Drawing.FontStyle)((System.Drawing.FontStyle.Bold | System.Drawing.FontStyle.Italic))), System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tsnLabel.Location = new System.Drawing.Point(29, 284);
            this.tsnLabel.Name = "tsnLabel";
            this.tsnLabel.Size = new System.Drawing.Size(142, 29);
            this.tsnLabel.TabIndex = 8;
            this.tsnLabel.Text = "TSN Floor:";
            this.tsnLabel.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // DebugForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(746, 467);
            this.Controls.Add(this.tsnLabel);
            this.Controls.Add(this.rttLabel);
            this.Controls.Add(this.t3Label);
            this.Controls.Add(this.fastRecoveryLabel);
            this.Controls.Add(this.windowSizeLabel);
            this.Controls.Add(this.rCreditsLabel);
            this.Controls.Add(this.normalRetryLabel);
            this.Controls.Add(this.retryLabel);
            this.Controls.Add(this.sendRateLabel);
            this.Name = "DebugForm";
            this.Text = "DebugForm";
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.DebugForm_FormClosing);
            this.Load += new System.EventHandler(this.DebugForm_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label sendRateLabel;
        private System.Windows.Forms.Label retryLabel;
        private System.Windows.Forms.Label normalRetryLabel;
        private System.Windows.Forms.Label rCreditsLabel;
        private System.Windows.Forms.Label windowSizeLabel;
        private System.Windows.Forms.Label fastRecoveryLabel;
        private System.Windows.Forms.Label t3Label;
        private System.Windows.Forms.Label rttLabel;
        private System.Windows.Forms.Label tsnLabel;
    }
}