using System;
using System.Collections.Generic;

namespace Step3_WebApi_WebApi.Models
{
	//interface for Dependecy injection into controller
	public interface IMockupData
	{
		//For Mockup only. In reality your data has to be threadsafe Lists or Database
        public List<Friend> Friends { get; init; }
        public List<GoodQuote> Quotes { get; init; }
    }


	public class MockupData : IMockupData
	{
		public List<Friend> Friends { get; init; } = new List<Friend>();
		public List<GoodQuote> Quotes { get; init; } = new List<GoodQuote>();

		public MockupData()
		{
			for (int i=0; i<100; i++)
			{
				Friends.Add(Friend.Factory.CreateRandom());
			}

			Quotes = CreateRandomData.AllQuotes;
		}
	}
}

