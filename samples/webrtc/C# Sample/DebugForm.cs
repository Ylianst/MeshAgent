using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

using OpenSource.WebRTC;

namespace WebRTC_Sample
{
    public partial class DebugForm : Form
    {
        private DateTime startTime = DateTime.Now;

        DateTime FastEnterTime;
        int FastResentPackets = 0;
        int NormalResentPackets = 0;
        int sackpackets = 0;
        int t3rtxcounter = 0;
        int tsncounter = 0;

        int totalBytes = 0;
        bool closing = false;
        private Random r = new Random();
        private WebRTCConnection mConnection;
        private WebRTCDataChannel mDataChannel;
        public DebugForm(WebRTCConnection connection)
        {
            InitializeComponent();
            Text = "WebRTC Debug View  -  NOT Connected";
            mConnection = connection;            
        }

        private async void DebugForm_Load(object sender, EventArgs e)
        {            
            mDataChannel = await mConnection.CreateDataChannel("DebugChannel");
            //mConnection._Debug_SetLossPercentage(5);
            
            await this.ContextSwitchToMessagePumpAsync();
            if (mDataChannel == null)
            {
                Text = "WebRTC Debug View  -  Error";
                return;
            }

            Text = "WebRTC Debug View  -  Connected";
            //mConnection.DebugEvents_OnReceiverCredits += mConnection_DebugEvents_OnReceiverCredits;
            mConnection.DebugEvents_OnSendFastRetry += mConnection_DebugEvents_OnSendFastRetry;
            mConnection.DebugEvents_OnSendRetry += mConnection_DebugEvents_OnSendRetry;
            mConnection.DebugEvents_OnHold += mConnection_DebugEvents_OnHold;
            mConnection.OnConnectionSendOk += mConnection_OnConnectionSendOk;
            mConnection.DebugEvents_OnCongestionWindowSizeChanged += mConnection_DebugEvents_OnCongestionWindowSizeChanged;

            mConnection.DebugEvents_OnFastRecovery += mConnection_DebugEvents_OnFastRecovery;
            //mConnection.DebugEvents_OnRTTCalculated += mConnection_DebugEvents_OnRTTCalculated;
            mConnection.DebugEvents_OnT3RTX += mConnection_DebugEvents_OnT3RTX;
            //mConnection.DebugEvents_OnTSNFloorNotRaised += mConnection_DebugEvents_OnTSNFloorNotRaised;

            //mConnection.DebugEvents_OnSACKReceived += mConnection_DebugEvents_OnSACKReceived;

            StartSendingJunk();
        }

        async void mConnection_DebugEvents_OnTSNFloorNotRaised(WebRTCConnection sender, int resendCounter)
        {
            tsncounter++;
            await this.ContextSwitchToMessagePumpAsync();

            tsnLabel.Text = "(" + tsncounter.ToString() + ") Resend Count: " + resendCounter.ToString();
        }

        async void mConnection_DebugEvents_OnT3RTX(WebRTCConnection sender, bool IsExpired, bool IsEnabled, int RTOValue)
        {
            await this.ContextSwitchToMessagePumpAsync();
            if (IsExpired) { t3Label.ForeColor = Color.DarkRed; ++t3rtxcounter; }
            if (!IsExpired && !IsEnabled) t3Label.ForeColor = Color.Black;
            if (IsEnabled) t3Label.ForeColor = Color.DarkGreen;

            t3Label.Text = "T3-RTX Timer [" + t3rtxcounter.ToString() + "]: " + (IsEnabled ? ("[ENABLED] " + RTOValue.ToString() + " ms") : "[DISABLED]");
        }

        async void mConnection_DebugEvents_OnRTTCalculated(WebRTCConnection sender, int SRTT)
        {
            await this.ContextSwitchToMessagePumpAsync();
            rttLabel.Text = "Round Trip Time: " + SRTT.ToString() + "ms calculated @" + DateTime.Now.ToLongTimeString();
        }

        async void mConnection_DebugEvents_OnFastRecovery(WebRTCConnection sender, bool EnterFastRecovery)
        {
            if (EnterFastRecovery) { FastEnterTime = DateTime.Now; FastResentPackets = 0; }
            await this.ContextSwitchToMessagePumpAsync();
            retryLabel.ForeColor = EnterFastRecovery ? Color.DarkGreen : Color.DarkRed;
            fastRecoveryLabel.Text = "Fast Recovery Mode: " + (EnterFastRecovery ? "[ENTERED]" : "[EXITED]");
        }

        async void mConnection_DebugEvents_OnSACKReceived(WebRTCConnection sender, uint TSN)
        {
            await this.ContextSwitchToMessagePumpAsync();
            rCreditsLabel.Text = "SACKs received: " + (++sackpackets).ToString();
        }

        async void mConnection_DebugEvents_OnCongestionWindowSizeChanged(WebRTCConnection sender, int windowSize)
        {
            await this.ContextSwitchToMessagePumpAsync();
            this.windowSizeLabel.Text = "Congestion Window Size: " + windowSize.ToString() + " bytes";
        }

        void mConnection_DebugEvents_OnHold(WebRTCConnection sender, int holdCount)
        {
        }

        async void mConnection_DebugEvents_OnSendRetry(WebRTCConnection sender, int retryCount)
        {
            NormalResentPackets += retryCount;
            int rate = (int)(((double)NormalResentPackets) / (DateTime.Now - startTime).TotalSeconds) / 1024;

            await this.ContextSwitchToMessagePumpAsync();
            normalRetryLabel.Text = "Normal Retry Rate: " + rate.ToString() + " KB/second";

        }

        async void mConnection_DebugEvents_OnSendFastRetry(WebRTCConnection sender, int retryCount)
        {
            FastResentPackets += retryCount;
            int rate = (int)(((double)FastResentPackets) / (DateTime.Now - FastEnterTime).TotalSeconds) / 1024;

            await this.ContextSwitchToMessagePumpAsync();
            retryLabel.Text = "Fast Retry Rate: " + rate.ToString() + " KB/second"; 
        }

        void mConnection_OnConnectionSendOk(WebRTCConnection sender)
        {
            StartSendingJunk();
        }

        async void mConnection_DebugEvents_OnReceiverCredits(WebRTCConnection sender, int receiverCredits)
        {
            if (receiverCredits < 0)
            {
                int x = 5;
            }
            await this.ContextSwitchToMessagePumpAsync();
            rCreditsLabel.Text = "Receiver Credits: " + receiverCredits.ToString(); 
        }

        void StartSendingJunk()
        {         
            Task.Run((Action)(async () =>
                {
                    int count = 0;
                    byte[] buffer = new byte[4096];
                    WebRTCDataChannel.SendStatus status;

                    if (totalBytes == 0 || (DateTime.Now - startTime).TotalSeconds > 10)
                    { 
                        startTime = DateTime.Now;
                        totalBytes = 0;
                        NormalResentPackets = 0;
                    }

                    if (closing) { return; }

                    do
                    {
                        r.NextBytes(buffer);
                        status = mDataChannel.Send(buffer);
                        count += buffer.Length;
                    } while (status == WebRTCDataChannel.SendStatus.ALL_DATA_SENT);

                    
                    
                    totalBytes += count;

                    count = (int)(((double)totalBytes) / (DateTime.Now - startTime).TotalSeconds)/1024;
                    if (!closing)
                    {
                        await this.ContextSwitchToMessagePumpAsync();
                        sendRateLabel.Text = "Send Rate: " + count.ToString() + " KBytes / second";
                    }
                }));        
        }

        private void DebugForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            closing = true;
        }

    }
}
