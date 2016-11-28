using Environment = MasterCard.Core.Model.Constants.Environment;
namespace MasterCard.Core.Model
{
    public interface ResourceConfigInterface {
        void SetEnvironment(Environment environment);

        void SetEnvironment(string host, string context);
    }
}