// Note :- We have made changes to this file and modified it according
// to our network topology used in the project.
// This file contains the implementation of TCPWestwood, RE and NewBRE.


/* -*-	Mode:C++; c-basic-offset:8; tab-width:8; indent-tabs-mode:t -*- */
/*
 * Copyright (c) 1990, 2001 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Lawrence Berkeley Laboratory,
 * Berkeley, CA.  The name of the University may not be used to
 * endorse or promote products derived from this software without
 * specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */


#define MYDEBUG 0
#define MYDEBUG_RTT 1
#define MYREPORT 0
#include <iostream>
#include <fstream>

#ifndef lint
static const char rcsid[] =
    "@(#) $Header: /mvalla/tcp-w-nr.cc,v 1.2 2001/09/17 15:12:29 mvalla Exp mvalla $ (LBL)";
#endif

//
// tcp-w-nr: a revised New Reno TCP source, with faster recovery
//

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <math.h>

#include "packet.h"
#include "ip.h"
#include "tcp.h"
#include "flags.h"
#include "address.h"

#include "tcp-westwood-plus.h"

static class WestwoodNRTcpClass : public TclClass {
public:
	WestwoodNRTcpClass() : TclClass("Agent/TCP/WestwoodNR") {}
	TclObject* create(int, const char*const*) {
		return (new WestwoodNRTcpAgent());
	}
} class_westwoodnr;

///// 
// WestwoodNRTcpAgent()
WestwoodNRTcpAgent::WestwoodNRTcpAgent() : NewRenoTcpAgent(),
  // these where originally in TcpAgent()
  current_bwe_(0), last_bwe_sample_(0), unaccounted_(0),
  fr_a_(0), min_rtt_estimate(5.0), myseqno_(1),last_ts_(0),last_echoed_ts_(0),last_seq_(0),
  lastackrx_(0.0), fr_alpha_(0.9), filter_type_(1), tau_(1.0), total_time_(0.0), total_size_(0.0), fr_prev_(20.0),
	start(0.0), cumAckedSegments(0.0), current_re_(0.0),
	fr_beta_(0.90476190476), fr_delta_(10.0), last_rtt_(0.0), rtt_max(0.0), rtt_last_max(0.0)

{
	printf("class handle %p\n", this);
	// Read defaults variables from ns-defaults.tcl

	// these where originally in TcpAgent()
	
	bind("current_bwe_", &current_bwe_);
	bind("last_bwe_sample_", &last_bwe_sample_);
  	bind("unaccounted_", &unaccounted_);
  	bind("fr_a_", &fr_a_);
	bind("fr_amin_", &fr_amin_);
	bind("fr_amax_", &fr_amax_);
	bind("fr_prev_", &fr_prev_);
  	bind("min_rtt_estimate", &min_rtt_estimate);

	bind("fr_alpha_", &fr_alpha_);
	bind("filter_type_", &filter_type_);
	bind("tau_", &tau_);
	bind("west_type_",&west_type_);
	bind("qest_",&qest_);
	bind("total_time_",&total_time_);
	bind("total_size_",&total_size_);
	bind("interp_type_",&interp_type_);

	bind("last_ts_",&last_ts_);
	bind("last_echoed_ts_",&last_echoed_ts_);
	bind("last_seq_",&last_seq_);
	bind("last_cwnd_",&last_cwnd_);
	bind("current_ts_",&current_ts_);
	bind("current_echoed_ts_",&current_echoed_ts_);

	// these where originally in NewRenoTcpAgent()
	bind("newreno_changes_", &newreno_changes_);
	bind("newreno_changes1_", &newreno_changes1_);
	bind("exit_recovery_fix_", &exit_recovery_fix_);
	bind("partial_window_deflation_", &partial_window_deflation_);
	bind("openadd_", &openadd_);
	bind("start", &start);
	bind("cumAckedSegments", &cumAckedSegments);
	bind("current_re_", &current_re_);

	bind("fr_beta_", &fr_beta_);
	bind("fr_delta_", &fr_delta_);
	bind("last_rtt_", &last_rtt_);
	bind("rtt_max", &rtt_max);
	bind("rtt_last_max",&rtt_last_max);
	//printf("Westwood New Reno binding done!\n");
}

///// 
// dupack_action()
void WestwoodNRTcpAgent::dupack_action()
{
	int recovered = (highest_ack_ > recover_);
        int allowFastRetransmit = allow_fast_retransmit(last_cwnd_action_);
        if (recovered || (!bug_fix_ && !ecn_) || allowFastRetransmit) {
                goto reno_action;
        }

        if (ecn_ && last_cwnd_action_ == CWND_ACTION_ECN) {
                last_cwnd_action_ = CWND_ACTION_DUPACK;
                /*
                 * What if there is a DUPACK action followed closely by ECN
                 * followed closely by a DUPACK action?
                 * The optimal thing to do would be to remember all
                 * congestion actions from the most recent window
                 * of data.  Otherwise "bugfix" might not prevent
                 * all unnecessary Fast Retransmits.
                 */
                reset_rtx_timer(1,0);
                output(last_ack_ + 1, TCP_REASON_DUPACK);
                return;
        }

        if (bug_fix_) {
                /*
                 * The line below, for "bug_fix_" true, avoids
                 * problems with multiple fast retransmits in one
                 * window of data.
                 */
                return;
        }

reno_action:

/*    
     if (ssthresh_ > cwnd_) {
	fr_a_+=0.25;
	if (fr_a_ > 4)
	  fr_a_=4;
      } else {
	fr_a_ = 1;
      }
  	ssthresh_ = (int)((current_bwe_/size_/8) * min_rtt_estimate);
      	if (cwnd_ > ssthresh_) {
      		cwnd_ = ssthresh_;
      	}
	*/

double fr_now = Scheduler::instance().clock();
double rtt_estimate = t_rtt_ * tcp_tick_;

if ((rtt_estimate < min_rtt_estimate)&&(rtt_estimate > 0)) {
		   min_rtt_estimate = rtt_estimate;
		}


/* west_type_ = 3 west+
   */



//if (west_type_<=4)fr_a_=-1;

double sstemp=(((current_bwe_*(min_rtt_estimate))/((double)(size_*8.0))));

if (sstemp < 2) sstemp = 2;
//if (sstemp1 < 2) sstemp1 = 2;


		ssthresh_ = (int)(sstemp);

		if (cwnd_ > sstemp) {cwnd_ = sstemp;}



	trace_event("TCPWNR_FAST_RETX");
        recover_ = maxseq_;
        last_cwnd_action_ = CWND_ACTION_DUPACK;
        // The slowdown was already performed
        // slowdown(CLOSE_SSTHRESH_HALF|CLOSE_CWND_HALF);
        reset_rtx_timer(1,0);
        output(last_ack_ + 1, TCP_REASON_DUPACK);
        return;

}

/////
// timeout()
void WestwoodNRTcpAgent::timeout(int tno)
{
	printf("*************************************timeout\n");
	/* retransmit timer */
	if (tno == TCP_TIMER_RTX) {
		if (highest_ack_ == maxseq_ && !slow_start_restart_) {
			/*
			 * TCP option:
			 * If no outstanding data, then don't do anything.
			 */
			return;
		};
		recover_ = maxseq_;
		if (highest_ack_ == -1 && wnd_init_option_ == 2)
			/* 
			 * First packet dropped, so don't use larger
			 * initial windows. 
			 */
			wnd_init_option_ = 1;
		if (highest_ack_ == maxseq_ && restart_bugfix_)
		       /* 
			* if there is no outstanding data, don't cut 
			* down ssthresh_.
			*/
			slowdown(CLOSE_CWND_ONE);
		else if (highest_ack_ < recover_ &&
		  last_cwnd_action_ == CWND_ACTION_ECN) {
		       /*
			* if we are in recovery from a recent ECN,
			* don't cut down ssthresh_.
			*/
			slowdown(CLOSE_CWND_ONE);
		}
		else {
			++nrexmit_;
			slowdown(CLOSE_FASTER);
		}
		/* if there is no outstanding data, don't back off rtx timer */
		if (highest_ack_ == maxseq_ && restart_bugfix_) {
			reset_rtx_timer(0,0);
		}
		else {
			reset_rtx_timer(0,1);
		}
		last_cwnd_action_ = CWND_ACTION_TIMEOUT;
		send_much(0, TCP_REASON_TIMEOUT, maxburst_);

	} 
	else {
		timeout_nonrtx(tno);
	}
}

///// 
// bwe_computation()
void WestwoodNRTcpAgent::bwe_computation(Packet *pkt) {
	
	hdr_tcp *tcph = hdr_tcp::access(pkt);
	double fr_now = Scheduler::instance().clock();
	hdr_flags *fh = hdr_flags::access(pkt);
	
	// last_ack_ indicates the ack no. of the ack received _before_
	// the current one 
	
	// START BWE COMPUTATION
  // Idea: cumulative ACKs acking more than 2 packets count for 1 packet
	//   since DUPACKs have already been accounted for
	int cumul_ack = tcph->seqno_ - last_ack_;
	int cumul_ack1 = cumul_ack; //used for queueing time estimation
	myseqno_ = tcph->seqno_;

	if (cumul_ack > 1) {

	  /* check if current ACK ACKs fewer or same number of segments than */
	  /* expected: if so, the missing ones were already accounted for by */
	  /* DUPACKs, and current ACK only counts as 1 */
	  if (unaccounted_ >= cumul_ack) {
	    unaccounted_-=cumul_ack;
	    cumul_ack=1;
	  } else
	  /* check if current ACK ACKs more segments than expected: if so,   */
	  /* part of them were already accounted for by DUPACKs; the rest    */

	  /* are cumulatively ACKed by present ACK. Make present ACK count   */
	  /* as the unacknowledged ACKs in excess*/
	  if (unaccounted_ < cumul_ack) {
	    cumul_ack-=unaccounted_;
	    unaccounted_=0;
	  }
	}

  /* if cumul_ack=0, the current ACK is clearly a DUPACK and should */
	/* count 1 */
	if (cumul_ack == 0) {
	  unaccounted_++;
	  cumul_ack=1;
	}

  /* safety check; if the previous steps are followed exactly,      */
	/* cumul_ack should not be >2 unless some strage events occur     */
	/* (e.g., an ACK is dropped on the way back and the following one */
	/* appears to ACK more than its due)                              */

	if (cumul_ack > 2) {
	  cumul_ack=2;
	  }



	nackpack_+= cumul_ack;
	last_seq_+=cumul_ack;
	//qest_=cwnd_-(current_bwe_*min_rtt_estimate)/(8.0*(double)size_);

	current_ts_=tcph->ts();
	current_echoed_ts_=tcph->ts_echo();

	double rtt_estimate = t_rtt_ * tcp_tick_;
	

	  if ((rtt_estimate < min_rtt_estimate)&&(rtt_estimate > 0)) {
		  min_rtt_estimate = rtt_estimate;
		qest_=0;
 		last_echoed_ts_=current_echoed_ts_;
 		last_ts_=current_ts_;
		}

	  if(fr_now-start>=rtt_estimate && rtt_estimate > 0){
		start = fr_now;
		double temp = size_ * 8 * cumAckedSegments;
		temp = temp/rtt_estimate;
		current_re_ = fr_alpha_*current_re_+(1-fr_alpha_)*temp;
		cumAckedSegments = 0.0;
	}
	 else{
		cumAckedSegments += cumul_ack;
		}

	rtt_max = fr_beta_ * rtt_last_max + ((1-fr_beta_)/2)*(rtt_estimate+last_rtt_);
 	last_rtt_ = rtt_estimate;
	if(rtt_estimate>rtt_last_max){
		rtt_last_max = rtt_estimate;
	}
	double d = rtt_estimate - min_rtt_estimate;
	double d_max = rtt_max - min_rtt_estimate;
	double fr_u = exp(-1*d*fr_delta_/d_max);
	//printf("rtt_estimate=%f, rtt_max=%f, min_rtt_estimate=%f, d=%f, d_max=%f, fr_u=%f fr_delta_=%f, out=%f\n",rtt_estimate, rtt_max, min_rtt_estimate, d, d_max, fr_u, fr_delta_,((-1*d*fr_delta_)/d_max));
	
		qest_=qest_+(current_ts_-last_ts_)-(current_echoed_ts_-last_echoed_ts_);
		last_echoed_ts_=current_echoed_ts_;
 		last_ts_=current_ts_;


//if (west_type_==5) qest_=cwnd_-(current_bwe_*min_rtt_estimate)/(8.0*(double)size_);



	int acked_size = size_ * 8 * cumul_ack;
	double ack_interv = fr_now - lastackrx_;
	double sample_bwe;
	double last_tmp_bwe;
	int idle_intervals;

	  sample_bwe = acked_size/ack_interv;
	  current_bwe_ = current_bwe_ * .93548 + 
	               (sample_bwe+last_bwe_sample_) * .03225;

	  last_bwe_sample_ = sample_bwe;


double re_estimate = fr_u*current_bwe_+(1-fr_u)*current_re_;


double sstemp=(((current_bwe_*(min_rtt_estimate))/((double)(size_*8.0))));
//double sstemp1=0.9*qest_+(((current_bwe_*(min_rtt_estimate))/((double)(size_*8.0))));

#if MYDEBUG
	hdr_ip *iph = hdr_ip::access(pkt);  
  	char *src_portaddr = Address::instance().print_portaddr(iph->sport());
	printf("sc%s: ack. no. %d at time %f, bwe=%f, cwnd = %d, ssthresh_ = %d\n",
	      src_portaddr, tcph->seqno_, fr_now, current_bwe_/1000000,
	      (int)cwnd_, (int)ssthresh_);
	printf("sc%s: now = %f, acked_size = %d, rxdiff = %f, last_ack_ = %d\n",
	         src_portaddr, fr_now, acked_size, (fr_now - lastackrx_), last_ack_);
	printf("sc%s: unaccounted_ = %d, fr_a_= %f, min_rtt_estimate = %f\n", 
			     src_portaddr, unaccounted_, fr_a_, min_rtt_estimate);
#endif
#if MYDEBUG_RTT
	hdr_ip *iph = hdr_ip::access(pkt);  
  	char *src_portaddr = Address::instance().print_portaddr(iph->sport());
	double f = t_rtt_ * tcp_tick_;
	//printf("source %s: %f cwnd=%d	      bwe=%f	  rtt=%f\n", 
	//     src_portaddr, fr_now, (int)cwnd_, current_bwe_/1000000, f);    
	printf("%p,%f,%f,%f,%f,%f,%f\n",this,re_estimate,current_re_,current_bwe_,sample_bwe,f,ack_interv);    
	//printf("%f,%f,%f,%f,%f,%f\n",re_estimate,current_re_,current_bwe_,sample_bwe,f,ack_interv);    
#endif	
#if MYREPORT	
	hdr_ip *iph = hdr_ip::access(pkt);  
	char *src_portaddr = Address::instance().print_portaddr(iph->src());
	printf("%s    %f      %d      %f      %d\n", 
	      src_portaddr, fr_now, (int)cwnd_, current_bwe_/1000000,
	      (int)ssthresh_);        
#endif		

	lastackrx_ = fr_now;
}


/////
// recv()
void WestwoodNRTcpAgent::recv(Packet *pkt, Handler* h)
{
	// START BWE COMPUTATION
	bwe_computation(pkt);
	//double cwndapp,sstreshapp;
	//cwndapp=cwnd_;
	//sstreshapp=ssthresh_;
	NewRenoTcpAgent::recv(pkt,h);
	/*if ((cwnd_>cwndapp)&&(cwndapp<sstreshapp))
	{
	cwnd_=cwnd_+openadd_; //a more aggressive slow start
	send_much(0, 0, maxburst_);
	}*/
}

/////////////////// Added by MV
// these where originally in TcpAgent()

/////
// slowdown()
void
WestwoodNRTcpAgent::slowdown(int how)
{
	double win, halfwin, decreasewin;
	int slowstart = 0;
	double fr_now = Scheduler::instance().clock();
	// we are in slowstart for sure if cwnd < ssthresh
	if (cwnd_ < ssthresh_)
		slowstart = 1;
	// we are in slowstart - need to trace this event
	trace_event("SLOW_START");

        if (precision_reduce_) {
		halfwin = windowd() / 2;
                if (wnd_option_ == 6) {
                        /* binomial controls */
                        decreasewin = windowd() - (1.0-decrease_num_)*pow(windowd(),l_parameter_);
                } else
	 		decreasewin = decrease_num_ * windowd();
		win = windowd();
	} else  {
		int temp;
		temp = (int)(window() / 2);
		halfwin = (double) temp;
                if (wnd_option_ == 6) {
                        /* binomial controls */
                        temp = (int)(window() - (1.0-decrease_num_)*pow(window(),l_parameter_));
                } else
	 		temp = (int)(decrease_num_ * window());
		decreasewin = (double) temp;
		win = (double) window();
	}
	if (how & CLOSE_SSTHRESH_HALF)
		// For the first decrease, decrease by half
		// even for non-standard values of decrease_num_.
		if (first_decrease_ == 1 || slowstart ||
			last_cwnd_action_ == CWND_ACTION_TIMEOUT) {
			// Do we really want halfwin instead of decreasewin
			// after a timeout?
			ssthresh_ = (int) halfwin;
		} else {
			ssthresh_ = (int) decreasewin;
		}
        else if (how & THREE_QUARTER_SSTHRESH)
		if (ssthresh_ < 3*cwnd_/4)
			ssthresh_  = (int)(3*cwnd_/4);
	if (how & CLOSE_CWND_HALF)
		// For the first decrease, decrease by half
		// even for non-standard values of decrease_num_.
		if (first_decrease_ == 1 || slowstart || decrease_num_ == 0.5) {
			cwnd_ = halfwin;
		} else cwnd_ = decreasewin;
        else if (how & CWND_HALF_WITH_MIN) {
		// We have not thought about how non-standard TCPs, with
		// non-standard values of decrease_num_, should respond
		// after quiescent periods.
                cwnd_ = decreasewin;
                if (cwnd_ < 1)
                        cwnd_ = 1;
	}
	///
	else if (how & CLOSE_FASTER) {
    	// TCP Westwood
	// this might be critical what with the coarseness of the timer;
    	// keep in mind that TCP computes the timeout as
    	//              (#of ticks) * (tick_duration)
    	// We need to do away with the coarseness...


	double rtt_estimate = t_rtt_ * tcp_tick_;

	  if ((rtt_estimate <= min_rtt_estimate)&&(rtt_estimate > 0)) {
		   min_rtt_estimate = rtt_estimate;
		}

	 double sstemp=(((current_bwe_*(min_rtt_estimate))/((double)(size_*8.0))));
			if (sstemp < 2) sstemp = 2;
			ssthresh_ = (int)(sstemp);
			cwnd_ = 2;

	}
//printf("set timeout = %f%f\n", fr_now,ssthresh_);


	else if (how & CLOSE_CWND_RESTART)
		cwnd_ = int(wnd_restart_);
	else if (how & CLOSE_CWND_INIT)
		cwnd_ = int(wnd_init_);
	else if (how & CLOSE_CWND_ONE)
		cwnd_ = 1;
	else if (how & CLOSE_CWND_HALF_WAY) {
		// cwnd_ = win - (win - W_used)/2 ;
		cwnd_ = W_used + decrease_num_ * (win - W_used);
                if (cwnd_ < 1)
                        cwnd_ = 1;
	}
	if (ssthresh_ < 2)
		ssthresh_ = 2;
	if (how & (CLOSE_CWND_HALF|CLOSE_CWND_RESTART|CLOSE_CWND_INIT|CLOSE_CWND_ONE))
		cong_action_ = TRUE;

	fcnt_ = count_ = 0;
	if (first_decrease_ == 1)
		first_decrease_ = 0;
}

/////
// newack()
/*
 * Process a packet that acks previously unacknowleged data.
 */


void WestwoodNRTcpAgent::newack(Packet* pkt)
{
	hdr_tcp *tcph = hdr_tcp::access(pkt);
	myseqno_ = tcph->seqno_;
	//call parent newack
	NewRenoTcpAgent::newack(pkt);
}

///// 
// delay_bind_dispatch()
//Westwood binds
int
WestwoodNRTcpAgent::delay_bind_dispatch(const char *varName, const char *localName, TclObject *tracer)
{

	if (delay_bind(varName, localName, "lastackno_", &lastackno_, tracer)) return TCL_OK;
	if (delay_bind(varName, localName, "lastackrx_", &lastackrx_, tracer)) return TCL_OK;
	if (delay_bind(varName, localName, "fr_alpha_", &fr_alpha_, tracer)) return TCL_OK;
	if (delay_bind(varName, localName, "filter_type_", &filter_type_, tracer)) return TCL_OK;
	if (delay_bind(varName, localName, "tau_", &tau_, tracer)) return TCL_OK;
	if (delay_bind(varName, localName, "mss_", &mss_, tracer)) return TCL_OK;
	if (delay_bind(varName, localName, "current_bwe_", &current_bwe_, tracer)) return TCL_OK;
       	if (delay_bind(varName, localName, "last_bwe_sample_", &last_bwe_sample_, tracer)) return TCL_OK;
	if (delay_bind(varName, localName, "unaccounted_", &unaccounted_, tracer)) return TCL_OK;
        if (delay_bind(varName, localName, "fr_a_", &fr_a_, tracer)) return TCL_OK;
        if (delay_bind(varName, localName, "min_rtt_estimate", &min_rtt_estimate, tracer)) return TCL_OK;
  	if (delay_bind(varName, localName, "myseqno_", &myseqno_, tracer)) return TCL_OK;
	
	// these where originally in NewRenoTcpAgent()
	if (delay_bind(varName, localName, "newreno_changes_", &newreno_changes_, tracer)) return TCL_OK;
	if (delay_bind(varName, localName, "newreno_changes1_", &newreno_changes1_, tracer)) return TCL_OK;
	if (delay_bind(varName, localName, "exit_recovery_fix_", &exit_recovery_fix_, tracer)) return TCL_OK;
	if (delay_bind(varName, localName, "partial_window_deflation_", &partial_window_deflation_, tracer)) return TCL_OK;

        return NewRenoTcpAgent::delay_bind_dispatch(varName, localName, tracer);
}

/* tickoff is the time since the clock last ticked when
 *  the packet we are using to compute the RTT was sent
 */

/* t_rtt_ is the number of ticks that have occurred so far,
 * starting from the tick BEFORE the packet was sent
 */


