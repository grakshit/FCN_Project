# compute the throughput given the trace file generated from NS2.
{
  event = $1
  time = $2
  packetsize = $8
  level = $4
  if (level == "AGT" && event == "s")
  {
    sent++
    if (!startTime || (time < startTime))
    {
      startTime = time
    }
  }

  if (level == "AGT" && event == "r")
  {
    receive++
    if (time > stopTime)
    {
      stopTime = time
    }
    recvdSize += packetsize
  }
}

END
{
  printf("Average Throughput in kbps= %.2f\n", (recvdSize/(stopTime-startTime)));
}
