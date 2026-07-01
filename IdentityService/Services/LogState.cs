namespace IdentityService.Services;

public class LogState
{
    private readonly ThreadLocal<string> _threadLocalLongTermLogState = new(() => "false");

    public string GetLongTermLogState()
    {
        return _threadLocalLongTermLogState.Value;
    }

    public void SetLongTermLogState(bool state)
    {
        _threadLocalLongTermLogState.Value = state.ToString();
    }
}
