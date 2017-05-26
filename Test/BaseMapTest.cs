

using System;
using System.Collections.Generic;
using NUnit.Framework;
using MasterCard.Core.Model;
using Newtonsoft.Json;


namespace TestMasterCard
{
	[TestFixture ()]
	public class BaseMapTest
	{
		[Test ()]
		public void TestAdd(){
			RequestMap map = new RequestMap ();
			map.Add("key1", "value1");

			Assert.AreEqual (1, map.Count);
			Assert.IsTrue(map.ContainsKey("key1"));
			Assert.AreEqual ("value1", map ["key1"]);

			//test negative
			Assert.IsFalse(map.ContainsKey("key2"));

		}


		[Test ()]
		public void TestAddWithConstructor(){
			RequestMap map = new RequestMap ("key1", "value1");

			Assert.AreEqual (1, map.Count);
			Assert.IsTrue(map.ContainsKey("key1"));
			Assert.AreEqual ("value1", map ["key1"]);

			//test negative
			Assert.IsFalse(map.ContainsKey("key2"));

		}

        [Test()]
        public void TestQKRFailure()
        {
            String jsob = "{\"automaticEmailReceipts\":false,\"cards\":[],\"countryOfResidence\":\"US\",\"defaultCardAlias\":null,\"emailAddress\":\"api3940125553341735testuser@ppol.com\",\"firstName\":\"Fred\",\"id\":\"153423\",\"lastName\":\"Smith\",\"marketingConsent\":false,\"masterPassMarketingConsent\":false,\"masterPassUser\":true,\"phoneNumber\":\"1411438513\",\"phoneNumberCountryCode\":\"1\",\"profilePhotoUrl\":\"https://sandbox.qkr.mastercard.com/qkrsandbox/api/v1/profile/image/153423\",\"requestCvcInAddCard\":\"true\",\"requestZipInAddCard\":\"REQUIRED\"}";
            new SmartMap(jsob);

        }


        [Test ()]
		public void TestNestedAdd(){
			RequestMap map = new RequestMap ();
			map.Add("key1.key2", "value1");

			Assert.AreEqual (1, map.Count);
			Assert.IsTrue(map.ContainsKey("key1"));
			Assert.IsTrue(map.ContainsKey("key1.key2"));
			Assert.AreEqual ("value1", map ["key1.key2"]);
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map["key1"]).Count);

			//test negative
			Assert.IsFalse(map.ContainsKey("key2"));
			Assert.IsFalse (map.ContainsKey ("key2.key1"));

		}


		[Test()]
		public void TestIssueWithMockResponse() {
			String responseString = "{  \n" + "   \"website\":\"hildegard.org\",\n" + "   \"address\":{  \n"
			                         + "      \"instructions\":{  \n" + "         \"doorman\":true,\n"
			                         + "         \"text\":\"some delivery instructions text\"\n" + "      },\n"
			                         + "      \"city\":\"New York\",\n" + "      \"postalCode\":\"10577\",\n" + "      \"id\":1,\n"
			                         + "      \"state\":\"NY\",\n" + "      \"line1\":\"2000 Purchase Street\"\n" + "   },\n"
			                         + "   \"phone\":\"1-770-736-8031\",\n" + "   \"name\":\"Joe Bloggs\",\n" + "   \"id\":1,\n"
			                         + "   \"email\":\"name@example.com\",\n" + "   \"username\":\"jbloggs\"\n" + "}";

			RequestMap tmpMap = new RequestMap (responseString);
			Assert.AreEqual ("hildegard.org", tmpMap ["website"]);	
			Assert.AreEqual ("some delivery instructions text", tmpMap ["address.instructions.text"]);	
			Assert.AreEqual ("true", tmpMap ["address.instructions.doorman"].ToString().ToLower());	

		}


		[Test()]
		public void TestIssueWithMockResponseAsDictionary() {
			String responseString = "{  \n" + "   \"website\":\"hildegard.org\",\n" + "   \"address\":{  \n"
				+ "      \"instructions\":{  \n" + "         \"doorman\":true,\n"
				+ "         \"text\":\"some delivery instructions text\"\n" + "      },\n"
				+ "      \"city\":\"New York\",\n" + "      \"postalCode\":\"10577\",\n" + "      \"id\":1,\n"
				+ "      \"state\":\"NY\",\n" + "      \"line1\":\"2000 Purchase Street\"\n" + "   },\n"
				+ "   \"phone\":\"1-770-736-8031\",\n" + "   \"name\":\"Joe Bloggs\",\n" + "   \"id\":1,\n"
				+ "   \"email\":\"name@example.com\",\n" + "   \"username\":\"jbloggs\"\n" + "}";

			RequestMap tmpMap = new RequestMap (RequestMap.AsDictionary(responseString));
			Assert.AreEqual ("hildegard.org", tmpMap ["website"]);	
			Assert.AreEqual ("some delivery instructions text", tmpMap ["address.instructions.text"]);	
			Assert.AreEqual ("true", tmpMap ["address.instructions.doorman"].ToString().ToLower());	

		}


		[Test ()]
		public void TestRemve(){
			RequestMap map = new RequestMap ();
			map.Add("key1", "value1");

			Assert.AreEqual (1, map.Count);
			Assert.IsTrue(map.ContainsKey("key1"));
			Assert.AreEqual ("value1", map ["key1"]);

			//test negative
			Assert.IsFalse(map.ContainsKey("key2"));

			map.Remove ("key1");
			Assert.AreEqual (0, map.Count);
			Assert.IsFalse(map.ContainsKey("key1"));


		}


        [Test()]
        public void TestInsertListWithMap()
        {
            RequestMap map = new RequestMap();
            map.Set("payment_transfer.transfer_reference", "10017018676132929870330");
            map.Set("payment_transfer.payment_type", "P2P");
            map.Set("payment_transfer.amount", "1000");
            map.Set("payment_transfer.currency", "USD");
            map.Set("payment_transfer.sender_account_uri", "pan:5013040000000018;exp=2017-08;cvc=123");
            map.Set("payment_transfer.sender.first_name", "John");
            map.Set("payment_transfer.sender.middle_name", "Tyler");
            map.Set("payment_transfer.sender.last_name", "Jones");
            map.Set("payment_transfer.sender.nationality", "USA");
            map.Set("payment_transfer.sender.date_of_birth", "1994-05-21");
            map.Set("payment_transfer.sender.address.line1", "21 Broadway");
            map.Set("payment_transfer.sender.address.line2", "Apartment A-6");
            map.Set("payment_transfer.sender.address.city", "OFallon");
            map.Set("payment_transfer.sender.address.country_subdivision", "MO");
            map.Set("payment_transfer.sender.address.postal_code", "63368");
            map.Set("payment_transfer.sender.address.country", "USA");
            map.Set("payment_transfer.sender.phone", "11234565555");
            map.Set("payment_transfer.sender.email", " John.Jones123@abcmail.com ");
            map.Set("payment_transfer.recipient_account_uri", "pan:5013040000000018;exp=2017-08;cvc=123");
            map.Set("payment_transfer.recipient.first_name", "Jane");
            map.Set("payment_transfer.recipient.middle_name", "Tyler");
            map.Set("payment_transfer.recipient.last_name", "Smith");
            map.Set("payment_transfer.recipient.nationality", "USA");
            map.Set("payment_transfer.recipient.date_of_birth", "1999-12-30");
            map.Set("payment_transfer.recipient.address.line1", "1 Main St");
            map.Set("payment_transfer.recipient.address.line2", "Apartment 9");
            map.Set("payment_transfer.recipient.address.city", "OFallon");
            map.Set("payment_transfer.recipient.address.country_subdivision", "MO");
            map.Set("payment_transfer.recipient.address.postal_code", "63368");
            map.Set("payment_transfer.recipient.address.country", "USA");
            map.Set("payment_transfer.recipient.phone", "11234567890");
            map.Set("payment_transfer.recipient.email", " Jane.Smith123@abcmail.com ");
            map.Set("payment_transfer.reconciliation_data.custom_field[0].name", " ABC");
            map.Set("payment_transfer.reconciliation_data.custom_field[0].value", " 123 ");
            map.Set("payment_transfer.reconciliation_data.custom_field[1].name", " DEF");
            map.Set("payment_transfer.reconciliation_data.custom_field[1].value", " 456 ");
            map.Set("payment_transfer.reconciliation_data.custom_field[2].name", " GHI");
            map.Set("payment_transfer.reconciliation_data.custom_field[2].value", " 789 ");
            map.Set("payment_transfer.statement_descriptor", "CLA*THANK YOU");
            map.Set("payment_transfer.channel", "KIOSK");
            map.Set("payment_transfer.funding_source", "DEBIT");
            map.Set("payment_transfer.text", "funding_source");

            Assert.AreEqual("{\"payment_transfer\":{\"transfer_reference\":\"10017018676132929870330\",\"payment_type\":\"P2P\",\"amount\":\"1000\",\"currency\":\"USD\",\"sender_account_uri\":\"pan:5013040000000018;exp=2017-08;cvc=123\",\"sender\":{\"first_name\":\"John\",\"middle_name\":\"Tyler\",\"last_name\":\"Jones\",\"nationality\":\"USA\",\"date_of_birth\":\"1994-05-21\",\"address\":{\"line1\":\"21 Broadway\",\"line2\":\"Apartment A-6\",\"city\":\"OFallon\",\"country_subdivision\":\"MO\",\"postal_code\":\"63368\",\"country\":\"USA\"},\"phone\":\"11234565555\",\"email\":\" John.Jones123@abcmail.com \"},\"recipient_account_uri\":\"pan:5013040000000018;exp=2017-08;cvc=123\",\"recipient\":{\"first_name\":\"Jane\",\"middle_name\":\"Tyler\",\"last_name\":\"Smith\",\"nationality\":\"USA\",\"date_of_birth\":\"1999-12-30\",\"address\":{\"line1\":\"1 Main St\",\"line2\":\"Apartment 9\",\"city\":\"OFallon\",\"country_subdivision\":\"MO\",\"postal_code\":\"63368\",\"country\":\"USA\"},\"phone\":\"11234567890\",\"email\":\" Jane.Smith123@abcmail.com \"},\"reconciliation_data\":{\"custom_field\":[{\"name\":\" ABC\",\"value\":\" 123 \"},{\"name\":\" DEF\",\"value\":\" 456 \"},{\"name\":\" GHI\",\"value\":\" 789 \"}]},\"statement_descriptor\":\"CLA*THANK YOU\",\"channel\":\"KIOSK\",\"funding_source\":\"DEBIT\",\"text\":\"funding_source\"}}",
                JsonConvert.SerializeObject(map));

        }

        [Test()]
        public void TestInsertListWithValue()
        {
            RequestMap map = new RequestMap();
            map.Set("payment_transfer.transfer_reference", "40013875384705044606252");
            map.Set("payment_transfer.payment_type", "P2P");
            map.Set("payment_transfer.funding_source[0]", "CREDIT");
            map.Set("payment_transfer.funding_source[1]", "DEBIT");
            map.Set("payment_transfer.amount", "1800");
            map.Set("payment_transfer.currency", "USD");
            map.Set("payment_transfer.sender_account_uri", "pan:5013040000000018;exp=2017-08;cvc=123");
            map.Set("payment_transfer.sender.first_name", "John");
            map.Set("payment_transfer.sender.middle_name", "Tyler");
            map.Set("payment_transfer.sender.last_name", "Jones");
            map.Set("payment_transfer.sender.nationality", "USA");
            map.Set("payment_transfer.sender.date_of_birth", "1994-05-21");
            map.Set("payment_transfer.sender.address.line1", "21 Broadway");
            map.Set("payment_transfer.sender.address.line2", "Apartment A-6");
            map.Set("payment_transfer.sender.address.city", "OFallon");
            map.Set("payment_transfer.sender.address.country_subdivision", "MO");
            map.Set("payment_transfer.sender.address.postal_code", "63368");
            map.Set("payment_transfer.sender.address.country", "USA");
            map.Set("payment_transfer.sender.phone", "11234565555");
            map.Set("payment_transfer.sender.email", " John.Jones123@abcmail.com ");
            map.Set("payment_transfer.recipient_account_uri", "pan:5013040000000018;exp=2017-08;cvc=123");
            map.Set("payment_transfer.recipient.first_name", "Jane");
            map.Set("payment_transfer.recipient.middle_name", "Tyler");
            map.Set("payment_transfer.recipient.last_name", "Smith");
            map.Set("payment_transfer.recipient.nationality", "USA");
            map.Set("payment_transfer.recipient.date_of_birth", "1999-12-30");
            map.Set("payment_transfer.recipient.address.line1", "1 Main St");
            map.Set("payment_transfer.recipient.address.line2", "Apartment 9");
            map.Set("payment_transfer.recipient.address.city", "OFallon");
            map.Set("payment_transfer.recipient.address.country_subdivision", "MO");
            map.Set("payment_transfer.recipient.address.postal_code", "63368");
            map.Set("payment_transfer.recipient.address.country", "USA");
            map.Set("payment_transfer.recipient.phone", "11234567890");
            map.Set("payment_transfer.recipient.email", " Jane.Smith123@abcmail.com ");
            map.Set("payment_transfer.reconciliation_data.custom_field[0].name", " ABC");
            map.Set("payment_transfer.reconciliation_data.custom_field[0].value", " 123 ");
            map.Set("payment_transfer.reconciliation_data.custom_field[1].name", " DEF");
            map.Set("payment_transfer.reconciliation_data.custom_field[1].value", " 456 ");
            map.Set("payment_transfer.reconciliation_data.custom_field[2].name", " GHI");
            map.Set("payment_transfer.reconciliation_data.custom_field[2].value", " 789 ");
            map.Set("payment_transfer.statement_descriptor", "CLA*THANK YOU");
            map.Set("payment_transfer.channel", "KIOSK");
            map.Set("payment_transfer.text", "funding_source");

            Assert.AreEqual("{\"payment_transfer\":{\"transfer_reference\":\"40013875384705044606252\",\"payment_type\":\"P2P\",\"funding_source\":[\"CREDIT\",\"DEBIT\"],\"amount\":\"1800\",\"currency\":\"USD\",\"sender_account_uri\":\"pan:5013040000000018;exp=2017-08;cvc=123\",\"sender\":{\"first_name\":\"John\",\"middle_name\":\"Tyler\",\"last_name\":\"Jones\",\"nationality\":\"USA\",\"date_of_birth\":\"1994-05-21\",\"address\":{\"line1\":\"21 Broadway\",\"line2\":\"Apartment A-6\",\"city\":\"OFallon\",\"country_subdivision\":\"MO\",\"postal_code\":\"63368\",\"country\":\"USA\"},\"phone\":\"11234565555\",\"email\":\" John.Jones123@abcmail.com \"},\"recipient_account_uri\":\"pan:5013040000000018;exp=2017-08;cvc=123\",\"recipient\":{\"first_name\":\"Jane\",\"middle_name\":\"Tyler\",\"last_name\":\"Smith\",\"nationality\":\"USA\",\"date_of_birth\":\"1999-12-30\",\"address\":{\"line1\":\"1 Main St\",\"line2\":\"Apartment 9\",\"city\":\"OFallon\",\"country_subdivision\":\"MO\",\"postal_code\":\"63368\",\"country\":\"USA\"},\"phone\":\"11234567890\",\"email\":\" Jane.Smith123@abcmail.com \"},\"reconciliation_data\":{\"custom_field\":[{\"name\":\" ABC\",\"value\":\" 123 \"},{\"name\":\" DEF\",\"value\":\" 456 \"},{\"name\":\" GHI\",\"value\":\" 789 \"}]},\"statement_descriptor\":\"CLA*THANK YOU\",\"channel\":\"KIOSK\",\"text\":\"funding_source\"}}",
            JsonConvert.SerializeObject(map));
        }



        [Test()]
        public void TestJsonParser()
        {
            string json = "{\"quote\":{\"quote_reference\":\"07124577927084921195\",\"proposals\":{\"proposal\":[{\"id\":\"prp_cDaukdMdb_IjzWmCs2tA6AyO5Fs\",\"resource_type\":\"proposal\",\"fees_included\":\"true\",\"charged_amount\":{\"currency\":\"USD\",\"amount\":\"105.00\"},\"credited_amount\":{\"currency\":\"MAD\",\"amount\":\"1000.00\"},\"principal_amount\":{\"currency\":\"USD\",\"amount\":\"100.00\"},\"expiration_date\":\"2016-09-27T03:43:32.109-05:00\",\"additional_data_list\":{\"resource_type\":\"list\",\"item_count\":\"2\",\"data\":{\"data_field\":[{\"name\":\"811\",\"value\":\"123\"},{\"name\":\"851\",\"value\":\"456\"}]}},\"quote_fx_rate\":\"123\"},{\"id\":\"prp_71iZdHSOlHGHH8wPZmIlSxhj_CM\",\"resource_type\":\"proposal\",\"fees_included\":\"true\",\"charged_amount\":{\"currency\":\"USD\",\"amount\":\"100.00\"},\"credited_amount\":{\"currency\":\"MAD\",\"amount\":\"950.00\"},\"principal_amount\":{\"currency\":\"USD\",\"amount\":\"100.00\"},\"expiration_date\":\"2016-09-27T03:53:32.109-05:00\",\"additional_data_list\":{\"resource_type\":\"list\",\"item_count\":\"2\",\"data\":{\"data_field\":[{\"name\":\"811\",\"value\":\"123\"},{\"name\":\"851\",\"value\":\"456\"}]}},\"quote_fx_rate\":\"123\"}]}}}";

            RequestMap response = new RequestMap(json);

            Assert.AreEqual(response.Get("quote.quote_reference"), "07124577927084921195");
            Assert.AreEqual(response.Get("quote.proposals.proposal[0].id"), "prp_cDaukdMdb_IjzWmCs2tA6AyO5Fs");
            Assert.AreEqual(response.Get("quote.proposals.proposal[0].resource_type"), "proposal");
            Assert.AreEqual(response.Get("quote.proposals.proposal[0].fees_included"), "true");
            Assert.AreEqual(response.Get("quote.proposals.proposal[0].charged_amount.currency"), "USD");
            Assert.AreEqual(response.Get("quote.proposals.proposal[0].charged_amount.amount"), "105.00");
            Assert.AreEqual(response.Get("quote.proposals.proposal[0].credited_amount.currency"), "MAD");
            Assert.AreEqual(response.Get("quote.proposals.proposal[0].credited_amount.amount"), "1000.00");
            Assert.AreEqual(response.Get("quote.proposals.proposal[0].principal_amount.currency"), "USD");
            Assert.AreEqual(response.Get("quote.proposals.proposal[0].principal_amount.amount"), "100.00");
            Assert.AreEqual(response.Get("quote.proposals.proposal[0].additional_data_list.resource_type"), "list");
            Assert.AreEqual(response.Get("quote.proposals.proposal[0].additional_data_list.item_count"), "2");
            Assert.AreEqual(response.Get("quote.proposals.proposal[0].additional_data_list.data.data_field[0].name"), "811");
            Assert.AreEqual(response.Get("quote.proposals.proposal[0].additional_data_list.data.data_field[0].value"), "123");
            Assert.AreEqual(response.Get("quote.proposals.proposal[0].additional_data_list.data.data_field[1].name"), "851");
            Assert.AreEqual(response.Get("quote.proposals.proposal[0].additional_data_list.data.data_field[1].value"), "456");
            Assert.AreEqual(response.Get("quote.proposals.proposal[0].quote_fx_rate"), "123");
            Assert.AreEqual(response.Get("quote.proposals.proposal[1].id"), "prp_71iZdHSOlHGHH8wPZmIlSxhj_CM");
            Assert.AreEqual(response.Get("quote.proposals.proposal[1].resource_type"), "proposal");
            Assert.AreEqual(response.Get("quote.proposals.proposal[1].fees_included"), "true");
            Assert.AreEqual(response.Get("quote.proposals.proposal[1].charged_amount.currency"), "USD");
            Assert.AreEqual(response.Get("quote.proposals.proposal[1].charged_amount.amount"), "100.00");
            Assert.AreEqual(response.Get("quote.proposals.proposal[1].credited_amount.currency"), "MAD");
            Assert.AreEqual(response.Get("quote.proposals.proposal[1].credited_amount.amount"), "950.00");
            Assert.AreEqual(response.Get("quote.proposals.proposal[1].principal_amount.currency"), "USD");
            Assert.AreEqual(response.Get("quote.proposals.proposal[1].principal_amount.amount"), "100.00");
            Assert.AreEqual(response.Get("quote.proposals.proposal[1].additional_data_list.resource_type"), "list");
            Assert.AreEqual(response.Get("quote.proposals.proposal[1].additional_data_list.item_count"), "2");
            Assert.AreEqual(response.Get("quote.proposals.proposal[1].additional_data_list.data.data_field[0].name"), "811");
            Assert.AreEqual(response.Get("quote.proposals.proposal[1].additional_data_list.data.data_field[0].value"), "123");
            Assert.AreEqual(response.Get("quote.proposals.proposal[1].additional_data_list.data.data_field[1].name"), "851");
            Assert.AreEqual(response.Get("quote.proposals.proposal[1].additional_data_list.data.data_field[1].value"), "456");
            Assert.AreEqual(response.Get("quote.proposals.proposal[1].quote_fx_rate"), "123");
        }



        [Test ()]
		public void TestReplace(){
			RequestMap map = new RequestMap ();
			map.Add("key1.key2", "value1");

			Assert.AreEqual (1, map.Count);
			//checl is it finds the key
			Assert.IsTrue(map.ContainsKey("key1"));
			//check if it find the nested keys
			Assert.IsTrue(map.ContainsKey("key1.key2"));
			// check if it find returns the correct value
			Assert.AreEqual ("value1", map ["key1.key2"]);
			// check if the first level map contains only one value
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map["key1"]).Count);


			map.Add("key1.key2", "value2");

			Assert.AreEqual (1, map.Count);
			//checl is it finds the key
			Assert.IsTrue(map.ContainsKey("key1"));
			//check if it find the nested keys
			Assert.IsTrue(map.ContainsKey("key1.key2"));
			// check if it find returns the correct value
			Assert.AreEqual ("value2", map ["key1.key2"]);
			// check if the first level map contains only one value
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map["key1"]).Count);
		}


		[Test ()]
		public void TesNestedAdd(){
			RequestMap map = new RequestMap ();
			map.Add("key1.key1", "value1");

			Assert.AreEqual (1, map.Count);
			//checl is it finds the key
			Assert.IsTrue(map.ContainsKey("key1"));
			//check if it find the nested keys
			Assert.IsTrue(map.ContainsKey("key1.key1"));
			// check if it find returns the correct value
			Assert.AreEqual ("value1", map ["key1.key1"]);
			// check if the first level map contains only one value
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map["key1"]).Count);


			map.Add("key1.key2", "value2");

			Assert.AreEqual (1, map.Count);
			//checl is it finds the key
			Assert.IsTrue(map.ContainsKey("key1"));
			//check if it find the nested keys
			Assert.IsTrue(map.ContainsKey("key1.key2"));
			// check if it find returns the correct value
			Assert.AreEqual ("value2", map ["key1.key2"]);
			// check if the first level map contains only one value
			Assert.AreNotSame(2, ((Dictionary<String,Object>) map["key1"]).Count);


		}


		[Test ()]
		public void TestConvertValueToMap()	{
			RequestMap map = new RequestMap ();
			map.Add("level1", "value1");
			Assert.Throws<InvalidCastException> (()=> { map.Add ("level1.level2", "level2");} );

		}


		[Test ()]
		public void TestMultipleAdd4Deep(){
			RequestMap map = new RequestMap ();
			map.Add("key1.key2.key3.key4", "value1");

			Assert.AreEqual (1, map.Count);
			//checl is it finds the key
			Assert.IsTrue(map.ContainsKey("key1"));
			Assert.IsTrue(map.ContainsKey("key1.key2"));
			Assert.IsTrue(map.ContainsKey("key1.key2.key3"));
			Assert.IsTrue(map.ContainsKey("key1.key2.key3.key4"));

			// check if it find returns the correct value
			Assert.AreEqual ("value1", map ["key1.key2.key3.key4"]);
			// check if the first level map contains only one value
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map["key1.key2.key3"]).Count);
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map["key1.key2"]).Count);
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map["key1"]).Count);

		}


		[Test ()]
		public void TestAdd4List(){
			RequestMap map = new RequestMap ();
			map.Add("key1", new List<String>() { "value1", "value2", "value3" });

			Assert.IsTrue(map.ContainsKey("key1"));
			Assert.AreEqual (3, ((List<String>) map ["key1"]).Count);

		}



		[Test ()]
		public void TestAddIndexed(){
			RequestMap map = new RequestMap ();
			map.Add("map[].name", "name1");
			map.Add("map[].name", "name2");
			map.Add("map[].name", "name3");

			Assert.AreEqual (1, map.Count);

			Assert.AreNotSame(1, ((List<Dictionary<String, Object>> ) map["map"]).Count); 
			//checl is it finds the key
			Assert.IsTrue(map.ContainsKey("map"));
			Assert.IsTrue(map.ContainsKey("map[0]"));
			Assert.IsTrue(map.ContainsKey("map[1]"));
			Assert.IsTrue(map.ContainsKey("map[2]"));
			Assert.IsFalse(map.ContainsKey("map[3]"));


			Assert.AreEqual ("name1", map ["map[0].name"]);
			Assert.AreEqual ("name2", map ["map[1].name"]);
			Assert.AreEqual ("name3", map ["map[2].name"]);

			// check if the first level map contains only one value
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map ["map[0]"]).Count);
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map ["map[1]"]).Count);
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map ["map[2]"]).Count);

		}

		[Test ()]
		public void TestConstructorDictionary(){

			Dictionary<String,Object> testDictionary = new Dictionary<string, object> ();
			testDictionary.Add ("boolean", true);
			testDictionary.Add ("double", 0.5);
			testDictionary.Add ("long", 1000);
			testDictionary.Add ("int", 16);
			testDictionary.Add ("list", new List<String>() {"one", "one", "one"});
			testDictionary.Add ("map", new Dictionary<String, String>() { {"0","one"}, { "1","one"}, {"2","one"}});

			RequestMap map = new RequestMap (testDictionary);

			Assert.AreEqual (6, map.Count);
			Assert.IsTrue(map.ContainsKey("boolean"));
			Assert.IsTrue(map.ContainsKey("double"));
			Assert.IsTrue(map.ContainsKey("long"));
			Assert.IsTrue(map.ContainsKey("int"));
			Assert.IsTrue(map.ContainsKey("list"));
			Assert.IsTrue(map.ContainsKey("map"));

			Assert.AreEqual (true, map ["boolean"]);
			Assert.AreEqual (0.5, map ["double"]);
			Assert.AreEqual (1000, map ["long"]);
			Assert.AreEqual (16, map ["int"]);
			Assert.AreEqual (3, ((List<String>) map ["list"]).Count);
			Assert.AreEqual (3, ((Dictionary<String, Object>) map ["map"]).Count);

		}

		[Test ()]
		public void TestConstructorBaseMap(){
			RequestMap map = new RequestMap ();
			map.Add("map[].name", "name1");
			map.Add("map[].name", "name2");
			map.Add("map[].name", "name3");

			Assert.AreEqual (1, map.Count);

			Assert.AreNotSame(1, ((List<Dictionary<String, Object>> ) map["map"]).Count); 
			//checl is it finds the key
			Assert.IsTrue(map.ContainsKey("map"));
			Assert.IsTrue(map.ContainsKey("map[0]"));
			Assert.IsTrue(map.ContainsKey("map[1]"));
			Assert.IsTrue(map.ContainsKey("map[2]"));
			Assert.IsFalse(map.ContainsKey("map[3]"));


			Assert.AreEqual ("name1", map ["map[0].name"]);
			Assert.AreEqual ("name2", map ["map[1].name"]);
			Assert.AreEqual ("name3", map ["map[2].name"]);

			// check if the first level map contains only one value
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map ["map[0]"]).Count);
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map ["map[1]"]).Count);
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map ["map[2]"]).Count);

			RequestMap newMap = new RequestMap (map);

			Assert.AreEqual (1, newMap.Count);

			Assert.AreNotSame(1, ((List<Dictionary<String, Object>> ) newMap["map"]).Count); 
			//checl is it finds the key
			Assert.IsTrue(newMap.ContainsKey("map"));
			Assert.IsTrue(newMap.ContainsKey("map[0]"));
			Assert.IsTrue(newMap.ContainsKey("map[1]"));
			Assert.IsTrue(newMap.ContainsKey("map[2]"));
			Assert.IsFalse(newMap.ContainsKey("map[3]"));


			Assert.AreEqual ("name1", newMap ["map[0].name"]);
			Assert.AreEqual ("name2", newMap ["map[1].name"]);
			Assert.AreEqual ("name3", newMap ["map[2].name"]);

			// check if the first level map contains only one value
			Assert.AreNotSame(1, ((Dictionary<String,Object>) newMap ["map[0]"]).Count);
			Assert.AreNotSame(1, ((Dictionary<String,Object>) newMap ["map[1]"]).Count);
			Assert.AreNotSame(1, ((Dictionary<String,Object>) newMap ["map[2]"]).Count);


		}



		[Test ()]
		public void TestReplaceIndexed(){
			RequestMap map = new RequestMap ();
			map.Add("map[].name", "name1");

			Assert.AreEqual (1, map.Count);

			Assert.AreNotSame(1, ((List<Dictionary<String, Object>> ) map["map"]).Count); 
			//checl is it finds the key
			Assert.AreEqual ("name1", map ["map[0].name"]);

			// check if the first level map contains only one value
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map ["map[0]"]).Count);


			map.Add("map[0].name", "name1_replaced");
			map.Add("map[0].surname", "surname");

			Assert.AreNotSame(2, ((List<Dictionary<String, Object>> ) map["map"]).Count); 

			Assert.AreEqual ("name1_replaced", map ["map[0].name"]);
			Assert.AreEqual ("surname", map ["map[0].surname"]);


		}


		[Test ()]
		public void TestAddIndexedWithOffset(){
			RequestMap map = new RequestMap ();



			Assert.DoesNotThrow(()=> { map.Add("map[1].name", "name1"); });



		}


		[Test ()]
		public void TestAddAll(){
			RequestMap map = new RequestMap ();

			Dictionary<String, Object> tmpDict = new Dictionary<String,Object> ();
			tmpDict.Add ("user.name", "andrea");
			tmpDict.Add ("user.surname", "rizzini");

			map.AddAll (tmpDict);

			Assert.AreEqual (1, map.Count);

			Assert.IsTrue(map.ContainsKey("user"));
			Assert.IsTrue(map.ContainsKey("user.name"));
			Assert.IsTrue(map.ContainsKey("user.surname"));

			Assert.AreEqual ("andrea", map ["user.name"]);
			Assert.AreEqual ("rizzini", map ["user.surname"]);

		}

		[Test ()]
		public void TestAddAllAsConstructor(){
			

			Dictionary<String, Object> tmpDict = new Dictionary<String,Object> ();
			tmpDict.Add ("user.name", "andrea");
			tmpDict.Add ("user.surname", "rizzini");

			RequestMap map = new RequestMap (tmpDict);

			Assert.AreEqual (1, map.Count);

			Assert.IsTrue(map.ContainsKey("user"));
			Assert.IsTrue(map.ContainsKey("user.name"));
			Assert.IsTrue(map.ContainsKey("user.surname"));

			Assert.AreEqual ("andrea", map ["user.name"]);
			Assert.AreEqual ("rizzini", map ["user.surname"]);

		}


		[Test ()]
		public void TestJson(){

			String tmpDict = " { \"user.name\":\"andrea\", \"user.surname\":\"rizzini\" }";

			RequestMap map = new RequestMap (tmpDict);

			Assert.AreEqual (1, map.Count);

			Assert.IsTrue(map.ContainsKey("user"));
			Assert.IsTrue(map.ContainsKey("user.name"));
			Assert.IsTrue(map.ContainsKey("user.surname"));

			Assert.AreEqual ("andrea", map ["user.name"]);
			Assert.AreEqual ("rizzini", map ["user.surname"]);
		}


		[Test ()]
		public void TestJson2(){

			String tmpDict = "{\n  \"mapName\": \"name\",\n  \"list\": [\n    {\n      \"itemId\": 1,\n      \"name\": \"name\",\n      \"list\": [\n         1, 2, 3, 4  \n      ]\n    },\n    {\n      \"itemId\": 2,\n      \"name\": \"name\",\n      \"list\": [\n         1, 2, 3, 4  \n      ]\n    },\n    {\n      \"itemId\": 3,\n      \"name\": \"name\",\n      \"list\": [\n         1, 2, 3, 4  \n      ]\n    }\n  ]\n}";

			SmartMap dict = new SmartMap(tmpDict);
			Assert.IsTrue (dict.ContainsKey ("mapName"));
			Assert.IsTrue (dict.ContainsKey ("list"));

			Assert.AreSame (typeof(List<Dictionary<String, Object>>), dict ["list"].GetType());

		}


	}



}

