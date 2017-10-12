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
using System.IO;
using System.Net;
using System.Text;
using System.Linq;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Collections.Generic;
using OpenSource.WebRTC;

namespace WebRTC_Sample
{
    /// <summary>
    /// Very simple HTTP/WebRTC rendez-vous server. It grabs a random local port and acts like a very basic HTTP server.
    /// It serves the WebRTC sample web page and handles offer/answer requests.
    /// </summary>
    public class SimpleRendezvousServer
    {
        private TcpListener mListener;
        private const int GET_HEADER = 542393671;
        private const int POST_HEADER = 1414745936;
        private const int END_HEADER = 168626701;

        public delegate WebRTCCommons.CustomAwaiter<byte[]> GetHandler(SimpleRendezvousServer sender, IPEndPoint from, string path);
        public delegate WebRTCCommons.CustomAwaiter<byte[]> PostHandler(SimpleRendezvousServer sender, string path, string body);

        public GetHandler OnGet;
        public PostHandler OnPost;

        private class ReadWrapper
        {
            public TcpClient client;
            public Stream s;
            public byte[] buffer;
            public int offset;
            public int totalRead;

            public ReadWrapper(TcpClient c, byte[] data)
            {
                buffer = data;
                offset = 0;
                totalRead = 0;
                client = c;
                s = client.GetStream();
            }
        }

        public SimpleRendezvousServer()
        {
            mListener = new TcpListener(new IPEndPoint(IPAddress.Any, 0));
            mListener.Start();
            //mListener.BeginAcceptSocket(OnAccept, null);
            mListener.BeginAcceptTcpClient(OnAccept, null);
        }

        public int Port { get { return ((mListener.LocalEndpoint as IPEndPoint).Port); } }

        private void OnAccept(IAsyncResult result)
        {
            try
            {
                TcpClient sock = mListener.EndAcceptTcpClient(result);
                ReadWrapper RW = new ReadWrapper(sock, new byte[32768]);
                RW.s.ReadAsync(RW.buffer, 0, RW.buffer.Length).ContinueWith((Action<Task<int>, object>)OnRead, RW);
            }
            catch { }
            mListener.BeginAcceptSocket(OnAccept, null);
        }

        private int GetContentLength(byte[] buffer, int offset, int count)
        {
            string[] headers = UTF8Encoding.UTF8.GetString(buffer, offset, count).Split(new string[] { "\r\n" }, StringSplitOptions.None);
            foreach (string header in headers)
            {
                if (header.IndexOf(":") > 0)
                {
                    string headerName = header.Substring(0, header.IndexOf(":")).Trim();
                    string headerValue = header.Substring(header.IndexOf(":") + 1).Trim();
                    if (headerName.ToUpper() == "CONTENT-LENGTH") { return (int.Parse(headerValue)); }
                }
            }
            return -1;
        }

        private async Task<byte[]> ProcessGet(IPEndPoint from, string value)
        {
            if (OnGet == null) return null;
            string path = "";
            try { path = value.Split(new string[] { " " }, StringSplitOptions.None)[1]; } catch { return null; }
            return await OnGet(this, from, path);
        }

        private async Task<byte[]> ProcessPost(string value, string body)
        {
            if (OnPost == null) return null;
            string path = "";
            try { path = value.Split(new string[] { " " }, StringSplitOptions.None)[1]; } catch { return null; }
            return await OnPost(this, path, body);
        }


        private async void OnRead(Task<int> t, object j)
        {
            ReadWrapper RW = j as ReadWrapper;
            RW.totalRead += t.Result;          

            if (RW.totalRead < 4)
            {
                RW.offset += t.Result;
                object jj = RW.s.ReadAsync(RW.buffer, RW.offset, RW.buffer.Length - RW.totalRead).ContinueWith((Action<Task<int>, object>)OnRead, RW);
                return;
            }

            int h = BitConverter.ToInt32(RW.buffer, 0);
            int eoh = -1;
            string[] headers = new string[0];

            switch (h)
            {
                case GET_HEADER:
                case POST_HEADER:
                    for (int i = 4; i < RW.totalRead; ++i) { if (BitConverter.ToInt32(RW.buffer, i) == END_HEADER) { eoh = i; break; } }
                    if (eoh > 0) { headers = UTF8Encoding.UTF8.GetString(RW.buffer, 0, RW.totalRead).Split(new string[] { "\r\n" }, StringSplitOptions.None); }
                    break;
                default:
                    break;
            }

            if (eoh > 0)
            {
                switch (h)
                {
                    case GET_HEADER:
                        byte[] resp = await ProcessGet(RW.client.Client.LocalEndPoint as IPEndPoint, headers[0]).ConfigureAwait(false);
                        if (resp.Length > 0) { RW.s.Write(resp, 0, resp.Length); }
                        RW.s.Close();
                        break;
                    case POST_HEADER:
                        // Check for Content-Length
                        int contentLength = -1;
                        foreach (string header in headers)
                        {
                            if (header.IndexOf(":") > 0)
                            {
                                string headerName = header.Substring(0, header.IndexOf(":")).Trim();
                                string headerValue = header.Substring(header.IndexOf(":") + 1).Trim();
                                if (headerName.ToUpper() == "CONTENT-LENGTH") { contentLength = (int.Parse(headerValue)); break; }
                            }
                        }
                        if (contentLength > 0)
                        {
                            if (contentLength + eoh + 4 <= RW.totalRead)
                            {
                                byte[] postResp = await ProcessPost(headers[0], UTF8Encoding.UTF8.GetString(RW.buffer, eoh + 4, contentLength)).ConfigureAwait(false);
                                if (postResp.Length > 0) { RW.s.Write(postResp, 0, postResp.Length); }
                                RW.s.Close();
                            }
                            else
                            {
                                RW.offset += t.Result;
                                object jj = RW.s.ReadAsync(RW.buffer, RW.offset, RW.buffer.Length - RW.totalRead).ContinueWith((Action<Task<int>, object>)OnRead, RW);
                            }
                        }
                        else
                        {
                            byte[] postResp = await ProcessPost(headers[0], null).ConfigureAwait(false);
                            if (postResp.Length > 0) { RW.s.Write(postResp, 0, postResp.Length); }
                            RW.s.Close();
                        }
                        break;
                }
            }
            else
            {
                RW.offset += t.Result;
                object jj = RW.s.ReadAsync(RW.buffer, RW.offset, RW.buffer.Length - RW.totalRead).ContinueWith((Action<Task<int>, object>)OnRead, RW);
            }
        }
    }
}
