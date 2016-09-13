using System;
using System.Collections.Generic;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using MySql.Data.MySqlClient;

namespace CapturingThePacketsWithoutTheCallback
{
    class Program
    {
        static void Main(string[] args)
        {
            string cs = @"server=localhost;userid=root;
            password=;database=pcap";

            MySqlConnection conn = null;

            conn = new MySqlConnection(cs);
            conn.Open();

            MySqlCommand cmd = new MySqlCommand();
            cmd.Connection = conn;
            cmd.CommandText = "ALTER TABLE packet_details AUTO_INCREMENT = 1";
            cmd.ExecuteNonQuery();

            /*cmd.CommandText = "INSERT INTO Authors(Name, Age) VALUES(@Name, @Age)";
            cmd.Prepare();
            */
            // Retrieve the device list from the local machine
            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;

            if (allDevices.Count == 0)
            {
                Console.WriteLine("No interfaces found! Make sure WinPcap is installed.");
                return;
            }

            // Print the list
            for (int i = 0; i != allDevices.Count; ++i)
            {
                LivePacketDevice device = allDevices[i];
                Console.Write((i + 1) + ". " + device.Name);
                if (device.Description != null)
                    Console.WriteLine(" (" + device.Description + ")");
                else
                    Console.WriteLine(" (No description available)");
            }

            int deviceIndex = 0;
            do
            {
                Console.WriteLine("Enter the interface number (1-" + allDevices.Count + "):");
                string deviceIndexString = Console.ReadLine();
                if (!int.TryParse(deviceIndexString, out deviceIndex) ||
                    deviceIndex < 1 || deviceIndex > allDevices.Count)
                {
                    deviceIndex = 0;
                }
            } while (deviceIndex == 0);

            // Take the selected adapter
            PacketDevice selectedDevice = allDevices[deviceIndex - 1];

            // Open the device
            using (PacketCommunicator communicator =
                selectedDevice.Open(65536,                                  // portion of the packet to capture
                // 65536 guarantees that the whole packet will be captured on all the link layers
                                    PacketDeviceOpenAttributes.NoCaptureLocal, // promiscuous mode
                                    1000))                                  // read timeout
            {
                using (BerkeleyPacketFilter filter = communicator.CreateFilter("ip and tcp"))
                {
                    // Set the filter
                    communicator.SetFilter(filter);
                }
                
                Console.WriteLine("Listening on " + selectedDevice.Description + "...");

                // Retrieve the packets
                Packet packet;
                do
                {
                    PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out packet);
                    switch (result)
                    {
                        case PacketCommunicatorReceiveResult.Timeout:
                            // Timeout elapsed
                            continue;
                        case PacketCommunicatorReceiveResult.Ok:
                           try
                              {
                                Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " SYN:" +
                                               packet.Ethernet.IpV4.Tcp.IsSynchronize + " ACK:" + packet.Ethernet.IpV4.Tcp.IsAcknowledgment);
                            }
                            catch (NullReferenceException on)
                            {
                                Console.WriteLine("Error: {0}", on.ToString());
                            }
                           try
                            {
                                cmd.CommandText = "INSERT INTO packet_details(Time_Stamp, Source_IP, Source_Port, Destination_IP, Destination_Port, SYN_Flag, ACK_Flag, Seq_Number, ACK_Number) VALUES('" + packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + "', '" + packet.Ethernet.IpV4.Source + "', " + packet.Ethernet.IpV4.Tcp.SourcePort + ", '" + packet.Ethernet.IpV4.Destination + "', " + packet.Ethernet.IpV4.Tcp.DestinationPort + ", '" + packet.Ethernet.IpV4.Tcp.IsSynchronize + "', '" + packet.Ethernet.IpV4.Tcp.IsAcknowledgment + "', " + packet.Ethernet.IpV4.Tcp.SequenceNumber + ", " + packet.Ethernet.IpV4.Tcp.AcknowledgmentNumber + ")";
                                cmd.ExecuteNonQuery();
                            }
                            catch (MySqlException ex)
                            {
                                Console.WriteLine("Error: {0}", ex.ToString());
                            }
                            catch (System.NullReferenceException)
                            {
                                cmd.CommandText = "INSERT INTO packet_details(Time_Stamp, Source_IP, Source_Port, Destination_IP, Destination_Port, SYN_Flag, ACK_Flag, Seq_Number, ACK_Number) VALUES('" + packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + "', '" + packet.Ethernet.IpV4.Source + "', 0, '" + packet.Ethernet.IpV4.Destination + "', 0, 'N', 'N', 0, 0)";
                                cmd.ExecuteNonQuery();
                            }
                            break;
                        default:
                            throw new InvalidOperationException("The result " + result + " shoudl never be reached here");
                    }
                } while (true);
            }
        }
    }
}