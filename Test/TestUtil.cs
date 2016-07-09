using System;
using NUnit.Framework;
using System.Text;

using MasterCard.Core;
using System.Collections.Generic;

namespace TestMasterCard
{
    /// <summary>
    /// Utils class for Testing
    /// </summary>
    public static class TestUtil
	{
        /// <summary>
        /// Assert functionality for handling Double and DateTime
        /// When XSDs were uploaded primitive types starting being returned
        /// Handles checking for Double and DateTime
        /// </summary>
        public static void assert(String s, Object o) {
            // 0.9320591049747101 was parsed as 0.93205910497471, assertion error due to precision
            if (o is Double) {
                double d1 = double.Parse(s);
                double d2 = (double) o;
                Assert.AreEqual(d1, d2);
            }
            // 2015-01-21T18:04:35-06:00 becomes a DateTime 1/19/2015 9:02:25 AM
            else if (o is DateTime) {
                Console.Out.WriteLine(s);
                Console.Out.WriteLine(o);

                DateTime dt1 = DateTime.Parse(s);
                DateTime dt2 = (DateTime) o;

                Assert.AreEqual(dt1, dt2);
            }
            else {
                Assert.That(s, Is.EqualTo(o.ToString()).IgnoreCase);
            }
        }
	}
}

