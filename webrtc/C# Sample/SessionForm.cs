/*
Copyright 2014 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

using System;
using System.Data;
using System.Linq;
using System.Text;
using System.Drawing;
using System.Threading;
using System.Windows.Forms;
using System.ComponentModel;
using System.Threading.Tasks;
using System.Collections.Generic;
using OpenSource.WebRTC;

namespace WebRTC_Sample
{
    public partial class SessionForm : Form
    {
        public bool isConnected
        {
            get
            {
                return (mConnected);
            }
        }
        private WebRTCConnection mConnection;
        private WebRTCDataChannel mData;
        private bool closing = false;
        private bool mConnected = false;

        private int mValue = new Random().Next(1, int.MaxValue);
        public int Value { get { return (mValue); } }
        public void SetStunServers(bool preserveOrder, params string[] servers)
        {
            if (!preserveOrder) { servers.Shuffle(); }
            mConnection.SetStunServers(servers);
        }

        public WebRTCConnection Connection { get { return (mConnection); } }
        public SessionForm()
        {
            InitializeComponent();

            mConnection = new WebRTCConnection();

            mConnection.OnConnected += mConnection_OnConnected;
            mConnection.OnDisconnected += mConnection_OnDisconnected;
            mConnection.OnDataChannel += mConnection_OnDataChannel;
            messageTextBox.Text += ("Got offer at " + DateTime.Now.ToShortTimeString() + ", buiding answer...\r\n");
            this.Text += " dPort: " + WebRTCConnection.StartDefaultLogger(0).ToString();
        }


        private async void GetOfferAsync(WebRTCCommons.CustomAwaiter<string> awaiter)
        {
            string sdp = await mConnection.GenerateOffer();
            awaiter.SetComplete(sdp);
        }
        public WebRTCCommons.CustomAwaiter<string> GetOffer()
        {
            WebRTCCommons.CustomAwaiter<string> retVal = new WebRTCCommons.CustomAwaiter<string>();
            GetOfferAsync(retVal);
            return (retVal);
        }

        void mConnection_OnDisconnected(WebRTCConnection sender)
        {
            mConnected = false;
            mConnection = null;
            if (!closing)
            {
                BeginInvoke((Action)(() =>
                {
                    Close();
                }));
            }
        }

        async void mConnection_OnConnected(WebRTCConnection sender)
        {
            mConnected = true;
            BeginInvoke((Action)(() =>
                {
                    messageTextBox.Text += ("Connected at " + DateTime.Now.ToShortTimeString() + "\r\n");
                    messageTextBox.Select(messageTextBox.Text.Length, 0);
                }));
            
            WebRTCDataChannel dc = await sender.CreateDataChannel("MyDataChannel"); // Wait to see if this is ACK'ed
            if (dc != null) 
            {
                // YUP
                mData = dc;
                mData.OnStringReceiveData += mData_OnStringReceiveData;
                mData.OnClosing += mData_OnClosing;
            }

            BeginInvoke(((Action<WebRTCDataChannel>)((d) =>
                {
                    messageTextBox.Text += ("Local DataChannel Creation (MyDataChannel) was " + (d != null ? "ACKed" : "NOT ACKed") + "\r\n");
                    messageTextBox.Select(messageTextBox.Text.Length, 0);
                    if (d != null)
                    {
                        inputTextBox.Enabled = true; // Only setting if true, because there could already be a dataChannel that has already enabled the textbox
                    }   
                })), dc);
        }

        void mData_OnClosing(WebRTCDataChannel sender)
        {
            try
            {
                BeginInvoke(((Action<WebRTCDataChannel>)((d) =>
                    {
                        messageTextBox.Text += ("Data Channel (" + d.ChannelName + ") was closed\r\n");
                        messageTextBox.Select(messageTextBox.Text.Length, 0);
                    })), sender);
            }
            catch(InvalidOperationException)
            {

            }
        }

        void mConnection_OnDataChannel(WebRTCConnection sender, WebRTCDataChannel DataChannel)
        {
            mData = DataChannel;
            mData.OnStringReceiveData += mData_OnStringReceiveData;

            BeginInvoke(((Action<WebRTCDataChannel>)((dc) =>
                {
                    messageTextBox.Text += ("DataChannel Created by Remote peer: (" + dc.ChannelName + "[" + dc.StreamId.ToString() + "]) was established\r\n");
                    messageTextBox.Select(messageTextBox.Text.Length, 0);
                    inputTextBox.Enabled = true;
                })), DataChannel);
        }

        void mData_OnStringReceiveData(WebRTCDataChannel sender, string data)
        {
            BeginInvoke(((Action<WebRTCDataChannel, string>)((dc, msg) =>
                {
                    messageTextBox.Text += ("Remote [" + dc.ChannelName + "]: " + msg + "\r\n");
                    messageTextBox.Select(messageTextBox.Text.Length, 0);
                })), sender, data);

        }

        private async void GetOfferResponseAsync(WebRTCCommons.CustomAwaiter<byte[]> awaiter, string offer)
        {
            string offerResponse = await mConnection.SetOffer(offer);
            byte[] r = UTF8Encoding.UTF8.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/sdp\r\nConnection: close\r\nContent-Length: " + offerResponse.Length.ToString() + "\r\n\r\n" + offerResponse);
            awaiter.SetComplete(r);
        }
        public WebRTCCommons.CustomAwaiter<byte[]> GetOfferResponse(string offer)
        {
            WebRTCCommons.CustomAwaiter<byte[]> retVal = new WebRTCCommons.CustomAwaiter<byte[]>();
            GetOfferResponseAsync(retVal, offer);           
            return (retVal);
        }

        private void sendButton_Click(object sender, EventArgs e)
        {
            if (inputTextBox.Text == "*CLOSE*")
            {
                mData.Close();
            }
            else if (inputTextBox.Text == "*PAUSE*")
            {
                mData.ParentConnection.Pause();
            }
            else if (inputTextBox.Text == "*RESUME*")
            {
                mData.ParentConnection.Resume();
            }
            else
            {
                mData.Send(inputTextBox.Text);
            }
            messageTextBox.Text += ("Local: " + inputTextBox.Text + "\r\n");
            inputTextBox.Text = "";
        }

        private void inputText_TextChanged(object sender, EventArgs e)
        {
            sendButton.Enabled = inputTextBox.Text != "";
        }

        private void inputText_KeyUp(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter && sendButton.Enabled) { sendButton_Click(sendButton, null); }
        }

        private void UserForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            closing = true;
            if (mConnection != null)
            {
                mConnection.Dispose();
            }
        }
    }
}
