/***********************************************************
*
* SLAD Test Application
*
*

     Copyright 2007-2008 AuthenTec B.V.


*
* Edit History:
*
*Initial revision
* Created.
**************************************************************/


/********************************************************
* Definitions and macros.
*********************************************************/
#include "c_sladtestapp.h"
#ifdef SLAD_TEST_BUILD_FOR_PE
#include "api_pec.h"
#include "slad_test_parser_op_defs.h"
#include "slad_test_interface_to_parser.h"
#include "slad_test.h"
#include "slad_test_pe.h"
#include "slad_test_pe_debug.h"
#include "slad_osal.h"

#ifdef TEST_INTERRUPT_COALESCING

#ifdef RT_EIP93_DRIVER
#define VPint *(volatile unsigned int *)
#endif
//Set this count equal to ADAPTER_EIP94V2_DESCRIPTORDONECOUNT
extern test_conf_data test_config_g;
extern pe_conf_data pe_conf_data_g;
extern test_device device_n_test_info_g;

static int packet_notification = 0;

static BYTE *result;
static int result_len;
static void *dst_copy;

static int failed;
static int InterruptReceivedCount = 0;
static int PacketGetCnt = 0;

static int app_id_s;
static DMABuf_Handle_t Handles[INTERRUPT_COALESCING_COUNT][MAX_HANDLES];

/* RT_EIP93_DRIVER
 * Should comment out "#ifndef TEST_BOUNCEBUFFERS" to pass compiling
 * errors if TEST_BOUNCEBUFFERS is undefined!
 */
#ifndef TEST_BOUNCEBUFFERS
static DMABuf_HostAddress_t Buffer_p[INTERRUPT_COALESCING_COUNT][MAX_HANDLES];
#endif
static PEC_ResultDescriptor_t PE_ResultDescr[INTERRUPT_COALESCING_COUNT];
static unsigned int GetCount;


typedef struct
{
    DMABuf_HostAddress_t DstBuf;
} Priv_Admin;

static Priv_Admin User[INTERRUPT_COALESCING_COUNT];
static void *User_p[INTERRUPT_COALESCING_COUNT];

static int intr_received = FALSE;
static int wait_timeout_notification = FALSE;

/* RT_EIP93_DRIVER
 * Should mark belowing 3 lnes to pass compiling errors if
 * TEST_BOUNCEBUFFERS is undefined!
 */
#ifdef TEST_BOUNCEBUFFERS
void *testbuf[MAX_HANDLES];
#endif

/************************************************************
*
*************************************************************/
static void
pe_validate_after_pkt_get (PEC_ResultDescriptor_t * Results_p, int cnt, // Packet Count after packet get
                           PEC_Status_t st, int PacketGetCnt)     // Status of Packet get
{
    int compare_len;
    uint8_t Status;


    if (User_p[PacketGetCnt] == Results_p->User_p)
      {
          /* Was packet gotten ok? */
          if (cnt)
            {
                if (device_n_test_info_g.tests.print_in_tests)
                  {
                      LOG_CRIT
                          ("\n\t Device returned the processed packet to the driver\n");
                  }

                // Copy the result to local buffer
                memcpy (dst_copy, Results_p->DstPkt_p,
                        Results_p->DstPkt_ByteCount);

                if (st == PEC_STATUS_OK)
                  {
                      // Pkt get was sucessful
                      compare_len =
                          (result_len <
                           Results_p->
                           DstPkt_ByteCount ? result_len : Results_p->
                           DstPkt_ByteCount);

                      /* Compare the processed packet data to the expected result. */
                      if ((memcmp
                           ((void *) dst_copy, (void *) result,
                            compare_len) == 0) && compare_len)
                        {
                            LOG_CRIT
                                ("\n\t <-: Result data matches expected data :-> \n");
                            if (device_n_test_info_g.tests.print_in_tests)
                              {
                                  LOG_CRIT ("\n\t Received Data:\n");
                                  Log_HexDump ("", 0,
                                               (unsigned char *) dst_copy,
                                               compare_len);
                                  LOG_CRIT ("\n");
                              }

                            if (Results_p->DstPkt_ByteCount != result_len)
                              {
                                  LOG_CRIT
                                      ("\n\t Warning : Received len [%d] did not match expected len [%d]\n",
                                       Results_p->DstPkt_ByteCount,
                                       result_len);

                                  failed = TRUE;

                              }

                        }
                      else
                        {
                            if (compare_len)
                              {
                                  failed = TRUE;
                                  LOG_CRIT
                                      ("\n\t <-: Result data did not match expected data :-> \n");
                                  if (device_n_test_info_g.tests.
                                      print_in_tests)
                                    {
                                        LOG_CRIT
                                            ("\n\t Anyway, Received Data is :\n");
                                        Log_HexDump ("", 0,
                                                     (unsigned char *)
                                                     dst_copy, compare_len);
                                        LOG_CRIT ("\n");
                                    }
                              }

                            if ((int) Results_p->DstPkt_ByteCount !=
                                result_len)
                              {
                                  LOG_CRIT
                                      ("\n\t  Received len [%d] did not match expected len [%d]\n",
                                       Results_p->DstPkt_ByteCount,
                                       result_len);
                              }


                            Status = (Results_p->Status1 >> 16) & (0xFF);
                            if (!Status)
                                LOG_CRIT
                                    ("\n\t KAT : packet processing pdr status=0x%04x\n",
                                     Status);

                            if (result_len == 0)
                              {
                                  LOG_CRIT ("\n\t len of output is 0 \n");
                              }
                            else
                                failed = TRUE;
                        }
                  }
                else
                  {
                      LOG_CRIT
                          ("\n\t KAT : failed to get packet, pkt_get status =0x%04x\n",
                           st);
                      failed = TRUE;
                  }
            }
          else
            {
                LOG_CRIT
                    ("\n\t No packet was received on calling slad_pkt_get() \n");
                failed = TRUE;
            }
      }
    else
      {
          LOG_CRIT ("\n\t Result mismatch with command \n");
          failed = TRUE;
      }
}


static void
pe_kat_pkt_get (void)
{
    PEC_Status_t st;
    if (wait_timeout_notification)
      {
          LOG_CRIT ("\n Callback not executed \n");
          failed = TRUE;
          return;
      }

    InterruptReceivedCount++;

    for (PacketGetCnt=0; PacketGetCnt<INTERRUPT_COALESCING_COUNT; PacketGetCnt++)
    {
          st = PEC_Packet_Get (&PE_ResultDescr[PacketGetCnt], 1, &GetCount);
          if(GetCount == 0)
            break;
          pe_validate_after_pkt_get (&PE_ResultDescr[PacketGetCnt], GetCount, st, PacketGetCnt);
    }
    
    intr_received = TRUE;    
}

static int
pe_kat (int app_id, PEC_Capabilities_t * di, pe_test_record * tr)
{
  UINT32 cnt;
  int src_alloc_len, src_len, dst_alloc_len, sa_len, srec_len;
  int ok = TRUE;
  void *src_copy = NULL, *sa_copy = NULL, *srec_copy = NULL;

  UINT32 i, pkt_count;
  DMABuf_Properties_t RequestedProp[INTERRUPT_COALESCING_COUNT][MAX_HANDLES];
  DMABuf_Status_t dma_status;
  PEC_CommandDescriptor_t PE_CommandDescr[INTERRUPT_COALESCING_COUNT];
  PEC_Status_t PE_Status;
  PEC_NotifyFunction_t CBFunc;
  DMABuf_Handle_t NULL_Handle1 = { 0 };
  DMABuf_Handle_t NULL_Handle2 = { 0 };
  bool SREC_IN_USE = false, ARC4_IN_USE = false;

  // Initialize the Command Descr
  memset (PE_CommandDescr, 0,
          sizeof (PEC_CommandDescriptor_t) * INTERRUPT_COALESCING_COUNT);

  dst_copy = NULL;

  LOG_CRIT ("\n Record no : %d \n", tr->record_number);

  src_alloc_len = tr->pkt_data.ip_buffer_len * sizeof (int);
  src_copy = osal_malloc (src_alloc_len);
  src_len = tr->pkt_data.ip_len_b;

  dst_alloc_len = tr->pkt_data.op_buffer_len * sizeof (int);
  dst_copy = osal_malloc (dst_alloc_len);

  sa_len = tr->ip_sa_record.sa_len * sizeof (int);
  sa_copy = osal_malloc (sa_len);

  if (!tr->ip_sa_record.is_arc4_srec_used)
    {
      srec_len = tr->ip_sa_record.srec_len * sizeof (int);
      if (srec_len)
        SREC_IN_USE = true;
    }
  else
    {
      srec_len = tr->ip_sa_record.arc4_srec_len * sizeof (int);
      if (srec_len)
        ARC4_IN_USE = true;
    }

  if (SREC_IN_USE || ARC4_IN_USE)
    srec_copy = osal_malloc (srec_len);

  result = osal_malloc (tr->pkt_data.op_buffer_len * sizeof (int));
  result_len = tr->pkt_data.op_len_b;

  if (src_copy == NULL || sa_copy == NULL)
    {
      LOG_CRIT ("\n\t Alloc failure : \n");
      return FALSE;
    }
  else
    {
      memcpy (sa_copy, tr->ip_sa_record.sa_words, sa_len);

      if (pe_conf_data_g.byte_swap_settings ==
          SLAD_TEST_PARSER_DEVICE_BYTE_SWAP_PD)
        {
          for (i = 0; i < tr->ip_sa_record.sa_len; i++)
            ((unsigned int *) sa_copy)[i] =
              osal_swap_endian (((unsigned int *) sa_copy)[i]);
        }


      if (sa_len == 128)
        {
          LOG_INFO ("\n\t This is Revision 1 SA \n");
        }
      else if (sa_len == 232)
        {
          LOG_INFO ("\n\t This is Revision 2 SA \n");
        }
      else
        {
          LOG_INFO ("\n\t Size of SA is : %d  \n", sa_len);
        }
      if (device_n_test_info_g.tests.print_in_tests)
        {
          LOG_CRIT ("\n SA is :\n");
          Log_HexDump ("", 0, sa_copy, sa_len);
        }
      if (device_n_test_info_g.tests.print_in_tests_detailed)
        slad_test_print_sa (sa_copy, sa_len / sizeof (UINT32));


      if (SREC_IN_USE)
        memcpy (srec_copy, tr->ip_sa_record.state_record, srec_len);

      if (ARC4_IN_USE)
        memcpy (srec_copy, tr->ip_sa_record.state_record +
                tr->ip_sa_record.arc4_srec_offset, srec_len);

      if (srec_len)
        {
          if (pe_conf_data_g.byte_swap_settings ==
              SLAD_TEST_PARSER_DEVICE_BYTE_SWAP_PD)
            {
              for (i = 0; i < tr->ip_sa_record.srec_len; i++)
                ((unsigned int *) srec_copy)[i] =
                  osal_swap_endian (((unsigned int *) srec_copy)[i]);
            }
        }

      if (device_n_test_info_g.tests.print_in_tests)
        {
          if (srec_len)
            {
              LOG_INFO ("\n State Record \n");
              Log_HexDump ("", 0, srec_copy, srec_len);
            }
        }

      memcpy (src_copy, tr->pkt_data.ip_buffer, src_alloc_len);
      
/* RT_EIP93_DRIVER_DEBUG
 * After C.L.'s new POF for fixing no_word_alignment, we don't
 * have to comment out "#define NO_SWAP_FOR_DATA"
 */ 
#define NO_SWAP_FOR_DATA

#ifndef NO_SWAP_FOR_DATA
    for (i = 0; i < tr->pkt_data.ip_buffer_len; i++)
        ((unsigned int *) src_copy)[i] =
            osal_swap_endian (((unsigned int *) src_copy)[i]);
#endif

      
      if (device_n_test_info_g.tests.print_in_tests)
        {
          LOG_CRIT ("\n Source data :\n");
          Log_HexDump ("", 0, src_copy, tr->pkt_data.ip_len_b);
        }

      memcpy (result, tr->pkt_data.op_buffer,
              tr->pkt_data.op_buffer_len * sizeof (int));
    }
    
#ifndef NO_SWAP_FOR_DATA

    for (i = 0; i < tr->pkt_data.op_buffer_len; i++)
        ((unsigned int *) result)[i] =
            osal_swap_endian (((unsigned int *) result)[i]);
#endif

  for (i = 0; i < INTERRUPT_COALESCING_COUNT; i++)
    {
      // src
      RequestedProp[i][0].Size = src_alloc_len;
      RequestedProp[i][0].Alignment = 4;
      RequestedProp[i][0].Bank = 0;
      RequestedProp[i][0].fCached = true;

      // dst
      RequestedProp[i][1].Size = dst_alloc_len;
      RequestedProp[i][1].Alignment = 4;
      RequestedProp[i][1].Bank = 0;
      RequestedProp[i][1].fCached = true;

      // SA
      RequestedProp[i][2].Size = sa_len;
      RequestedProp[i][2].Alignment = 4;
      RequestedProp[i][2].Bank = 0;
      RequestedProp[i][2].fCached = true;

      // Srec
      if (SREC_IN_USE || ARC4_IN_USE)
        {
          RequestedProp[i][3].Size = srec_len;
          RequestedProp[i][3].Alignment = 4;
          RequestedProp[i][3].Bank = 0;
          RequestedProp[i][3].fCached = true;
        }
    }

  for (pkt_count = 0; pkt_count < INTERRUPT_COALESCING_COUNT; pkt_count++)
    {
      // allocate src buffer
      dma_status = DMABuf_Alloc (RequestedProp[pkt_count][0],
                                 &Buffer_p[pkt_count][0],
                                 &Handles[pkt_count][0]);

      memcpy (Buffer_p[pkt_count][0].p, src_copy, src_alloc_len);

      // allocate destination buffer
      dma_status = DMABuf_Alloc (RequestedProp[pkt_count][1],
                                 &Buffer_p[pkt_count][1],
                                 &Handles[pkt_count][1]);

      // allocate sa buffer
      dma_status = DMABuf_Alloc (RequestedProp[pkt_count][2],
                                 &Buffer_p[pkt_count][2],
                                 &Handles[pkt_count][2]);

      memcpy (Buffer_p[pkt_count][2].p, sa_copy, sa_len);

      // allocate srec buffer
      if (SREC_IN_USE || ARC4_IN_USE)
        {
          dma_status = DMABuf_Alloc (RequestedProp[pkt_count][3],
                                     &Buffer_p[pkt_count][3],
                                     &Handles[pkt_count][3]);

          memcpy (Buffer_p[pkt_count][3].p, srec_copy, srec_len);
        }
      else
        {
          Buffer_p[pkt_count][3].p = NULL;
        }

      if (dma_status != DMABUF_STATUS_OK)
        {
          LOG_CRIT ("\n DMABuf_Alloc failed with error code %d: i:%d",
                    dma_status, i);
          return FALSE;
        }

      // Store the address of the dest DMA buffer for priv administration
      User[pkt_count].DstBuf = Buffer_p[pkt_count][0];  //Dst Buf
      User_p[pkt_count] = &User[pkt_count];
    }

  for (i = 0; i < INTERRUPT_COALESCING_COUNT; i++)
    {
      if (device_n_test_info_g.tests.print_in_tests)
        {
          LOG_CRIT ("\n SA is :\n");
          Log_HexDump ("", 0, sa_copy, sa_len);
          LOG_CRIT ("\n State Record \n");
          Log_HexDump ("", 0, srec_copy, srec_len);
          LOG_CRIT ("\n Source data :\n");
          Log_HexDump ("", 0, src_copy, src_alloc_len);
        }

      // Fill in Command Descr
      PE_CommandDescr[i].User_p = User_p[i];
      PE_CommandDescr[i].SrcPkt_Handle = Handles[i][0];
      PE_CommandDescr[i].DstPkt_Handle = Handles[i][1];
      PE_CommandDescr[i].SrcPkt_ByteCount = src_alloc_len;

      PE_CommandDescr[i].SA_WordCount = sa_len / sizeof (UINT32);
      PE_CommandDescr[i].SA_Handle1 = Handles[i][2];

      if (SREC_IN_USE || ARC4_IN_USE)
        PE_CommandDescr[i].SA_Handle2 = Handles[i][3];
      else
        PE_CommandDescr[i].SA_Handle2 = NULL_Handle1;

      PE_CommandDescr[i].Control1 = tr->pkt_data.pd_words[0];
      PE_CommandDescr[i].Control2 = tr->pkt_data.pd_words[2];
    }

    // Interrupt_Enable & Interrrupt_SetHandler for IRQ_RDR_THRESH_IRQ
    CBFunc = pe_kat_pkt_get;
    PEC_ResultNotify_Request (CBFunc, INTERRUPT_COALESCING_COUNT);

    cnt = 1;
    for(pkt_count =0; pkt_count<INTERRUPT_COALESCING_COUNT; pkt_count++)
    {
       // Register SA (Handle[2]), Srec  (Handle[3])
       if (SREC_IN_USE)
            PEC_SA_Register (Handles[pkt_count][2], Handles[pkt_count][3],
                             NULL_Handle1);
       else if (ARC4_IN_USE)
            PEC_SA_Register (Handles[pkt_count][2], NULL_Handle1,
                             Handles[pkt_count][3]);
       else
          PEC_SA_Register (Handles[pkt_count][2], NULL_Handle1, NULL_Handle2);

       
    }
    
    //Submit packets in one put call
    {
       PE_Status = PEC_Packet_Put (PE_CommandDescr, INTERRUPT_COALESCING_COUNT, &cnt);
       
       if ((PE_Status == PEC_STATUS_OK) && cnt)
         {
             LOG_CRIT ("\n[coalescing_newapi] Packets submitted to the device, cnt:%d \n", cnt);
             ok = TRUE;
         }
      else
         {
             LOG_CRIT ("\n\t Failed to put  packet, drvstat=0x%08x\n",
                       PE_Status);
             ok = FALSE;
             goto free_buffers;
         }
        
    }
    
#if 0
    //EndianSwap Setting for C.L.'s new POF for fix no_word_alignment  (put right b4 kick CryptoEngine)
    VPint(0xbfb70100) = 0x00040700;
    VPint(0xbfb701d0) = 0x00e4001b;
    //trigger Crypto Engine here, instead of in EIP93_WriteCB
    VPint(0xbfb70090) = (uint32_t)cnt;
#endif

    {
        int TIMEOUT_VALUE;

        osal_delay (TEST_DELAY_TIMER);
        TIMEOUT_VALUE = TEST_BUSYWAIT_COUNT;
        do
          {
              osal_delay (TEST_DELAY_TIMER);
              TIMEOUT_VALUE--;
          }
        while (!intr_received && TIMEOUT_VALUE >= 0);

        if (!intr_received)
          {
              wait_timeout_notification = TRUE; // buffers can be freed safely
              LOG_CRIT ("\n Interrupt not received \n");
              failed = TRUE;
          }
        else
          {
              LOG_CRIT ("\n Interrupt received \n");
              if((InterruptReceivedCount != 1) || (PacketGetCnt != INTERRUPT_COALESCING_COUNT))
                {
                  LOG_CRIT ("\n %d Interrupt Coalescing Test Failed \n", InterruptReceivedCount);
                  LOG_CRIT ("\n %d packets received for 1 interrupt. \n", PacketGetCnt);
                  failed = TRUE;
                }
              else
                {
                  LOG_CRIT ("\n %d interrupts received. \n", InterruptReceivedCount);
                  LOG_CRIT ("\n %d packets received. \n", PacketGetCnt);
		  if(failed != TRUE)
                  	LOG_CRIT ("\n Interrupt Coalescing Test Passed \n");
#ifdef RT_EIP93_DRIVER
                  //reset InterruptReceivedCount, otherwise "Interrupt Coalescing Test Failed" will show.
                  InterruptReceivedCount = 0;
#endif
                }
#ifdef RT_EIP93_DRIVER
                //reset intr_received, otherwise the second time you execute the script, tasklet pe_kat_pkt_get will not run.
                intr_received = FALSE;
#endif
          }
    }
free_buffers:

  osal_free (src_copy, src_alloc_len);
  osal_free (dst_copy, dst_alloc_len);
  osal_free (sa_copy, sa_len);
  if (SREC_IN_USE || ARC4_IN_USE)
    osal_free (srec_copy, srec_len);

  if (result)
    {
      osal_free (result, tr->pkt_data.op_buffer_len * sizeof (int));
      result = NULL;
    }

  for (i = 0; i < INTERRUPT_COALESCING_COUNT; i++)
    {
      if (SREC_IN_USE)
        PEC_SA_UnRegister (Handles[i][2], Handles[i][3], NULL_Handle1);
      else if (ARC4_IN_USE)
        PEC_SA_UnRegister (Handles[i][2], NULL_Handle1, Handles[i][3]);
      else
        PEC_SA_UnRegister (Handles[i][2], NULL_Handle1, NULL_Handle2);

      /* Free all allocated items. */
      DMABuf_Release (Handles[i][0]);
      DMABuf_Release (Handles[i][1]);
      DMABuf_Release (Handles[i][2]);

      if (SREC_IN_USE || ARC4_IN_USE)
        DMABuf_Release (Handles[i][3]);
    }
  return ok;
}

/***********************************************************************
*
************************************************************************/
int
slad_test_pe_int_coalescing_run_test (
        int app_id,
        PEC_Capabilities_t * di,
        pe_test_record * tr,
        int notification)
{
    int r = 0;
    
    packet_notification = notification;
    InterruptReceivedCount = 0;

    app_id_s = app_id;

    LOG_CRIT ("\n");

    if (device_n_test_info_g.tests.test_case_id_string[0] != 0)
        LOG_CRIT ("Test Case : %s \n",
                  device_n_test_info_g.tests.test_case_id_string);

    LOG_CRIT ("\n{ :-> Known-result-test (KAT) \n");

    if (packet_notification)
        LOG_CRIT ("\n Interrupt Coalescing Mode \n");
    else
        LOG_CRIT ("\n Polling Mode \n");


    failed = FALSE;

    r = pe_kat (app_id_s, di, tr);

    return (r & !failed);
}
#endif //TEST_INTERRUPT_COALESCING
#endif
