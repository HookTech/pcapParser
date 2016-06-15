#include<iostream>
#include<string>
#include<vector>
#include<set>
#include<map>
#include<fstream>
#include<Winsock2.h>
using namespace std;
#include"pcap.h"
#pragma comment(lib,"ws2_32.lib")//��̬����lib�ļ�

string path="C:\\Users\\philo\\Desktop\\";
fstream outstream;//�ļ���

struct block{
	unsigned long s;
	unsigned long e;
};

map<u_Int16,vector<block>> lossList;
map<u_Int16,unsigned long> curr;

inline bool isContain(block &a,block &b){//�ж�a�Ƿ����b
	if(a.s<=b.s && a.e>=b.e)
		return true;
	else
		return false;
}

map<u_Int16,unsigned long> history_loss;//lossList��ʷ�����ۼӣ�Ҳ���Ƕ���Ķ�����������out of order��
map<u_Int16,unsigned long> fill_loss;//��ʷ���hole����

string longtoip(unsigned long ip)
{
	string s=".";
	s=s+to_string((_Longlong)(ip>>24));
	ip=ip&0x00FFFFFF;
	s="."+to_string((_Longlong)(ip>>16))+s;
	ip=ip&0x0000FFFF;
	s="."+to_string((_Longlong)(ip>>8))+s;
	ip=ip&0x000000FF;
	s=to_string(_Longlong(ip))+s;
	return s;
}

inline double selfDefinedDivision(double a, double b){
	return b !=0 ? a/b:0;
}

struct retrans_pair{
	double retrans;
	double totals;
};
map<_Int32, retrans_pair> retrans_record;//��¼������<ʱ��ֱ��ʣ�������¼��>
_Int32 interval = 10*1000;//ʱ����Ժ���Ϊ��λ
_Int32 manual_inittime = 5*60*1000;//�Զ���Ŀ�ʼʱ��

double cur_relative_time = 0;//��manual_inittime��ʼ�����ʱ��
_Int32 cur_seq,for_seq = 0;//��ǰ����һ��ack���к�
_Int32 ackcount = 0;//��¼ack�ظ��Ĵ���
double retranscount,totalcount = 0;//�ش��ĸ������ܵĸ���
_Int32 trigger = 1;//������¼�����кţ�Ҳ�ǵڼ���interval�����к�
bool isfirst = true;//��ʼ�����


int read_pcap(string pcap_path,vector<string> & ip_list,int &loss,int &retran,vector<string> &outList){
	struct _packet_header packetheader;
	struct FrameHeader_t frameheader;
	struct IpHeader_t ipheader;
	struct TcpHeader_t tcpheader;
	FILE *pfile=fopen(pcap_path.c_str(),"rb");
	if (pfile==0)
	{
		cout<<"open pcap file failed!"<<endl;
		exit(1);
	}
	fseek(pfile,0,SEEK_END);//�ڲ�ָ�뵽�ļ�β
	long filelen=ftell(pfile);//�ڲ�ָ��������ļ��׵�ƫ���ֽ�
	fseek(pfile,0,SEEK_SET);//�ƶ�ָ�����ļ�ͷ
	Byte * pbuffer=new Byte[filelen];
	fread((void*)pbuffer,1,filelen,pfile);//һ���԰��ļ�������
	//cout << filelen << endl;
	fclose(pfile);
	//Byte *tcpbytes=new Byte[20];

	for(vector<string>::iterator it=ip_list.begin();it!=ip_list.end();it++){
		//cout << *it << endl;
		int iIndex=sizeof(struct _pcap_header);//24
		double initTime=0.0;
		int flag=0;
		map<u_Int16,unsigned int> initSeqIn, initSeqOut;//map��ֵ��--��ʼ����ź�ȷ�Ϻ� in(<---) out(--->)
		map<u_Int16,unsigned int> initAckOut;
		set<_Int32> remoteIp;
		int count1=0;
		unsigned int tcpoffset=0;
		unsigned int ipheaderlen=0;
		string listItem="";//�����
		u_Int16 filter_port=0;//��ǰ�Ķ˿ں�

		unsigned long curr_record=0;//�㷨��ǰ�ļ�¼ֵ

		cur_relative_time = 0;//��manual_inittime��ʼ�����ʱ��
		cur_seq = 0;//��ǰack���к�
		for_seq = 0;//��һ��ack���к�
		ackcount = 0;//��¼ack�ظ��Ĵ���
		retranscount = 0;//�ش��ĸ���
		totalcount = 0;//�ܵĸ���
		trigger = 1;//������¼�����кţ�Ҳ�ǵڼ���interval�����к�
		isfirst = true;//��ʼ�����

		while(iIndex<=filelen){
			listItem="";
			//��ȡpacketheader
			memcpy((void*)&packetheader,(void*)(pbuffer+iIndex),sizeof(struct _packet_header));
			if(0==flag){
				initTime=packetheader.iTimeSecond*1000+packetheader.iTimeSS/1000.0;
				flag=1;
			}
			//��ȡframeheader
			memcpy((void*)&frameheader,(void*)(pbuffer+iIndex+sizeof(struct _packet_header)),sizeof(FrameHeader_t));
			if(frameheader.FrameType==8)
			{//IP
				//��ȡIPheader
				memcpy((void*)&ipheader,(void*)(pbuffer+iIndex+sizeof(struct _packet_header)+sizeof(struct FrameHeader_t)),sizeof(struct IpHeader_t));
				if((int)ipheader.Protocal==6&&(longtoip(ipheader.SrcIP)==*it||longtoip(ipheader.DstIP)==*it))
				{//TCP
					ipheaderlen=ipheader.Ver_HLen&15;//ȡ����λ
					//��ȡtcpheader
					memcpy((void*)&tcpheader,(void*)(pbuffer+iIndex+sizeof(struct _packet_header)+sizeof(struct FrameHeader_t)+ipheaderlen*4),sizeof(struct TcpHeader_t));
					//memcpy((void*)tcpbytes,(void*)(pbuffer+iIndex+sizeof(struct _packet_header)+sizeof(struct FrameHeader_t)+ipheaderlen*4),20);
					count1++;
					tcpoffset=(tcpheader.dataoffset>>4)*4;//tcpͷ����С
					short tcploadlen=(ntohs(ipheader.TotalLen)-ipheaderlen*4-tcpoffset);//tcp���ݶδ�С
					if(longtoip(ipheader.SrcIP)==*it && longtoip(ipheader.DstIP)!="172.16.66.3" && ntohs(tcpheader.dstPort)!=20)//�򱾵ش�����
					{
						/*
						if(remoteIp.count(ntohs(tcpheader.dstPort))==0)
						{
							initSeqIn.insert(make_pair(ntohs(tcpheader.dstPort),0));
							initSeqOut.insert(make_pair(ntohs(tcpheader.srcPort),0));
						}
						*/
						if(tcpheader.flag==18)
						{//ACK=1,SYN=1
							initSeqIn[ntohs(tcpheader.dstPort)]=ntohl(tcpheader.sequence_num);
							initAckOut[ntohs(tcpheader.dstPort)]=ntohl(tcpheader.sequence_num);
							lossList[ntohs(tcpheader.dstPort)].clear();
							block init={0,0};
							lossList[ntohs(tcpheader.dstPort)].push_back(init);
							curr[ntohs(tcpheader.dstPort)]=0;
							history_loss[ntohs(tcpheader.dstPort)]=0;
							fill_loss[ntohs(tcpheader.dstPort)]=0;

							if(ntohs(tcpheader.dstPort)!=filter_port)
							{
								outList.push_back("###split###");
								outstream << "###split###" << endl;
								filter_port=ntohs(tcpheader.dstPort);//���µ�ǰ�Ķ˿�
							}
						}
						unsigned int tmp=initSeqIn[ntohs(tcpheader.dstPort)];
						unsigned long relative_seq_s=ntohl(tcpheader.sequence_num)-initSeqIn[ntohs(tcpheader.dstPort)];
						unsigned long relative_seq_e;
						if(tcploadlen!=0)
							relative_seq_e=relative_seq_s+tcploadlen-1;
						else
							relative_seq_e=relative_seq_s;
						/*
						listItem+=to_string((long double)count1)+"\t"+
								to_string((long double)(packetheader.iTimeSecond*1000+packetheader.iTimeSS/1000.0-initTime))+"\t"+
								longtoip(ipheader.SrcIP)+":"+to_string((long double)ntohs(tcpheader.srcPort))+"-->"+
								longtoip(ipheader.DstIP)+":"+to_string((long double)ntohs(tcpheader.dstPort))+"\t"+
								to_string((long double)tcploadlen)+"\t["+to_string((long double)relative_seq_s)+"~"+to_string((long double)relative_seq_e)+"]";
						*/
						outstream << count1 << "\t" << std::fixed << packetheader.iTimeSecond*1000+packetheader.iTimeSS/1000.0-initTime << "\t" <<
								longtoip(ipheader.SrcIP) << ":" << to_string((long double)ntohs(tcpheader.srcPort)) << "-->" <<
								longtoip(ipheader.DstIP) << ":" << to_string((long double)ntohs(tcpheader.dstPort)) <<"\t" << 
								to_string((long double)tcploadlen)+"\t[" << std::fixed << relative_seq_s << "~" << std::fixed << relative_seq_e << "]";
						if(relative_seq_s==relative_seq_e && relative_seq_s!=0){//�������tcp��ͷ��û������
							iIndex+=sizeof(struct _packet_header)+packetheader.iLength;
							//listItem+="\t[empty]";
							outstream << "\t[empty]" << endl;
							outList.push_back(listItem);
							continue;
						}
						//���з����㷨��ʼ
						block in={relative_seq_s,relative_seq_e};
						bool isIn=false;
						bool isSame=false;
						block tmp1,tmp2;
						//��lossList�в������İ��Ƿ������hole��
						vector<block>::iterator er=lossList[ntohs(tcpheader.dstPort)].end();
						for(vector<block>::iterator it=lossList[ntohs(tcpheader.dstPort)].begin();it!=lossList[ntohs(tcpheader.dstPort)].end();it++){
							if(isContain(*it,in)){
								isIn=true;
								if((*it).s==in.s && (*it).e!=in.e){
									(*it).s=in.e+1;
									if(in.e==0 && in.s==0)
										;
									else
										fill_loss[ntohs(tcpheader.dstPort)]+=in.e-in.s+1;
									//listItem+="\t[fill_hole:"+to_string((long double)fill_loss[ntohs(tcpheader.dstPort)])+"]";
									outstream << "\t[fill_hole:" <<std::fixed << fill_loss[ntohs(tcpheader.dstPort)] << "]";
								}
								else if((*it).s!=in.s && (*it).e==in.e){
									(*it).e=in.s-1;
									if(in.e==0 && in.s==0)
										;
									else
										fill_loss[ntohs(tcpheader.dstPort)]+=in.e-in.s+1;
									//listItem+="\t[fill_hole:"+to_string((long double)fill_loss[ntohs(tcpheader.dstPort)])+"]";
									outstream << "\t[fill_hole:"<< std::fixed << fill_loss[ntohs(tcpheader.dstPort)] << "]";
								}
								else if((*it).s!=in.s && (*it).e!=in.e){
									tmp1.s=(*it).s;
									tmp1.e=in.s-1;
									tmp2.s=in.e+1;
									tmp2.e=(*it).e;
									er=it;
								}
								else if((*it).s==in.s && (*it).e==in.e){
									er=it;
									isSame=true;
								}
							}
						}
						if(er!=lossList[ntohs(tcpheader.dstPort)].end()){
							lossList[ntohs(tcpheader.dstPort)].erase(er);
							if(!isSame){
								lossList[ntohs(tcpheader.dstPort)].push_back(tmp1);
								lossList[ntohs(tcpheader.dstPort)].push_back(tmp2);
							}
							if(in.e==0 && in.s==0)
								;
							else
								fill_loss[ntohs(tcpheader.dstPort)]+=in.e-in.s+1;
							//listItem+="\t[fill_hole:"+to_string((long double)fill_loss[ntohs(tcpheader.dstPort)])+"]";
							outstream << "\t[fill_hole:"<< std::fixed << fill_loss[ntohs(tcpheader.dstPort)] << "]";
						}
						if(!isIn){//���������hole�İ�,�����İ�
							if(in.s==curr[ntohs(tcpheader.dstPort)]+1){
								curr[ntohs(tcpheader.dstPort)]=in.e;
							}
							else if(in.e<=curr[ntohs(tcpheader.dstPort)]){
								//listItem+="\t[dup]";
								outstream << "\t[dup]";
							}
							else{
								block holeblock={curr[ntohs(tcpheader.dstPort)]+1,in.s-1};
								lossList[ntohs(tcpheader.dstPort)].push_back(holeblock);
								curr[ntohs(tcpheader.dstPort)]=in.e;
								history_loss[ntohs(tcpheader.dstPort)]+=holeblock.e-holeblock.s+1;
								//listItem+="\t[history_hole:"+to_string((long double)history_loss[ntohs(tcpheader.dstPort)])+"]";
								outstream << "\t[history_hole:" << std::fixed << history_loss[ntohs(tcpheader.dstPort)] << "]";
							}
						}
						outstream << endl;

						curr_record=curr[ntohs(tcpheader.dstPort)];//��¼�㷨��ǰǰ������seq
						
						if (tcploadlen >0)
							totalcount++;//��¼�����ܰ���

					}
					else if(longtoip(ipheader.SrcIP)!="172.16.66.3" && ntohs(tcpheader.srcPort)!=20)//���ⷢ��ACK����Ϣ
					{
						/*
						if(remoteIp.count(ntohs(tcpheader.dstPort))==0)
						{
							initSeqIn.insert(make_pair(ntohs(tcpheader.srcPort),0));
							initSeqOut.insert(make_pair(ntohs(tcpheader.srcPort),0));
						}
						*/
						if(tcpheader.flag==2)
						{//SYN=1
							initSeqOut[ntohs(tcpheader.srcPort)]=ntohl(tcpheader.sequence_num);
							if(ntohs(tcpheader.srcPort)!=filter_port){
								outstream << "###split###" << endl;
								outList.push_back("###split###");
								filter_port=ntohs(tcpheader.srcPort);
							}
						}
						_Int32 ack=ntohl(tcpheader.ACK_num)-initAckOut[ntohs(tcpheader.srcPort)];
						/*
						listItem+=to_string((long double)count1)+"\t"+
								to_string((long double)(packetheader.iTimeSecond*1000+packetheader.iTimeSS/1000.0-initTime))+"\t"+
								longtoip(ipheader.SrcIP)+":"+to_string((long double)ntohs(tcpheader.srcPort))+"-->"+
								longtoip(ipheader.DstIP)+":"+to_string((long double)ntohs(tcpheader.dstPort))+"\t"+
								to_string((long double)tcploadlen);
						*/
						outstream << count1 << "\t" << std::fixed << (packetheader.iTimeSecond*1000+packetheader.iTimeSS/1000.0-initTime) << "\t"
							<< longtoip(ipheader.SrcIP) << ":" << ntohs(tcpheader.srcPort) << "-->" << longtoip(ipheader.DstIP) << ":" << ntohs(tcpheader.dstPort) << "\t"
							<< tcploadlen <<"\t"<< "["<< ack << "]"<< std::fixed << "\t[curr:" << curr_record << "]"<< endl;
						cur_relative_time = packetheader.iTimeSecond*1000+packetheader.iTimeSS/1000.0-initTime-manual_inittime;
						if (cur_relative_time < 0 || ack < 0.001){
							iIndex+=sizeof(struct _packet_header)+packetheader.iLength;
							continue;
						}
						if (isfirst){
							trigger = cur_relative_time / interval + 1;
							isfirst = false;
						}

						if (cur_relative_time / interval <= trigger){
							for_seq = ack;
							if (for_seq == cur_seq){
								if (++ackcount == 2){
									ackcount = 0;
									retranscount++;//��¼�ش���
								}
							}
							else{ ackcount = 0;}
							cur_seq = for_seq;
						}
						else{
							//retrans_record[trigger] = selfDefinedDivision(retranscount,totalcount);
							//retrans_record[trigger].retrans+=retranscount;
							//retrans_record[trigger].totals+=totalcount;
							if (retrans_record.count(trigger) == 0){
								retrans_pair p = {retranscount, totalcount};
								retrans_record.insert(make_pair(trigger,p));
							}
							else{
								retrans_record[trigger].retrans+=retranscount;
								retrans_record[trigger].totals+=totalcount;
							}
							trigger = cur_relative_time / interval + 1;
							totalcount = 0, retranscount = 0;
						}
					}
					outList.push_back(listItem);
				}//end if frame
			}
			iIndex+=sizeof(struct _packet_header)+packetheader.iLength;
		}//end while
	}//end for
	delete pbuffer;
	pbuffer=0;
	return 0;
}

int main(int argc, char **argv){
	vector<string> ip_list;
	vector<string> outputList;
	string name,pcap_name;
	/*
	ip_list.push_back("61.155.219.85");
	ip_list.push_back("202.102.68.79");
	pcap_name="rtmfp_upload3.pcap";
	*/
	
	cout << "please input your file path:" << endl;
	cout << path;
	cin >> pcap_name;
	
	string temp_ip="";
	cout << "please input your ip filters:(\"ok\" end)" << endl;
	while(1){
		cin >> temp_ip;
		if(temp_ip!="ok")
			ip_list.push_back(temp_ip);
		else
			break;
	}
	
	int loss=0,retran=0;
	name=pcap_name.substr(0,pcap_name.rfind('.'))+".txt";
	outstream.open(path+name,fstream::out);
	outstream.clear();
	read_pcap(path+pcap_name,ip_list,loss,retran,outputList);
	fstream retranstream;
	retranstream.open(path+"tcp_retrans.txt",fstream::out);
	retranstream.clear();
	map<_Int32,retrans_pair>::const_iterator iter = retrans_record.begin();
	while (iter != retrans_record.end()){
		retranstream << std::fixed << (*iter).first << "\t" << std::fixed << selfDefinedDivision((*iter).second.retrans, (*iter).second.totals) << endl;
		iter++;
	}
	retranstream.close();
	/*
	for(vector<string>::iterator it=outputList.begin();it!=outputList.end();it++)
		outstream << *it << endl;
	*/
	outstream.close();
	unsigned long hole=0;
	unsigned long fill=0;
	unsigned long diff=0;
	vector<u_Int16> tags;
	map<u_Int16,unsigned long>::const_iterator it=history_loss.begin();
	if(history_loss.size()==fill_loss.size()){
		while(it!=history_loss.end()){
			tags.push_back((*it).first);
			it++;
		}
		for(vector<u_Int16>::const_iterator i=tags.begin();i!=tags.end();i++){
			//cout << *i << endl;
			diff+=history_loss[*i]-fill_loss[*i];
			hole+=history_loss[*i];
			fill+=fill_loss[*i];
		}
	}
	cout << "hole:" << hole << endl;
	cout << "fill:" << fill << endl;
	cout << "diff:" << diff <<endl;
	system("pause");
	return 0;
}