using System.Collections.ObjectModel;

namespace NetWarden.Client.ViewModels;

public static class ListSync
{
    /// <summary>
    /// Makes <paramref name="target"/> equal to <paramref name="desired"/> using
    /// Move/Insert/Remove, so unchanged items keep their identity (and the grid keeps
    /// selection and scroll position) across refreshes.
    /// </summary>
    public static void Sync<T>(ObservableCollection<T> target, IReadOnlyList<T> desired) where T : class
    {
        for (int i = 0; i < desired.Count; i++)
        {
            T item = desired[i];
            if (i < target.Count && ReferenceEquals(target[i], item))
                continue;

            int existing = -1;
            for (int j = i + 1; j < target.Count; j++)
            {
                if (ReferenceEquals(target[j], item))
                {
                    existing = j;
                    break;
                }
            }

            if (existing >= 0)
                target.Move(existing, i);
            else
                target.Insert(i, item);
        }

        while (target.Count > desired.Count)
            target.RemoveAt(target.Count - 1);
    }
}
