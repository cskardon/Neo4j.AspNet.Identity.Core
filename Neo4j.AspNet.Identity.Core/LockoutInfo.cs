namespace Neo4j.AspNet.Identity.Core
{
    using System;
    using Newtonsoft.Json;

    public class LockoutInfo
    {
        public DateTimeOffset? EndDate { get; internal set; }
        public bool Enabled { get; internal set; }
        public int AccessFailedCount { get; internal set; }

        [JsonIgnore]
        public bool AllPropertiesAreSetToDefaults =>
            EndDate == null &&
            Enabled == false &&
            AccessFailedCount == 0;

        public const string Label = "LockOut";
    }
}