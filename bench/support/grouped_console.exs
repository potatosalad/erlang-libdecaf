defmodule LibdecafBench.GroupedConsole do
  @moduledoc "Render Benchee's default output separately for each curve and operation."
  @behaviour Benchee.Formatter

  @impl true
  def format(suite, options) do
    suite.scenarios
    |> Enum.map(fn scenario ->
      [curve, operation, library] = String.split(scenario.name, " / ")
      [group | _] = String.split(operation, " (", parts: 2)
      name = library <> String.replace_prefix(operation, group, "")
      {{curve, group}, %{scenario | name: name}}
    end)
    |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
    |> Enum.sort_by(&elem(&1, 0))
    |> Enum.map(fn {{curve, operation}, scenarios} ->
      group = %{
        suite
        | scenarios: scenarios,
          configuration: %{suite.configuration | title: "#{curve} / #{operation}"}
      }

      # Rebase slowdown ratios and sort against the fastest operation in this group.
      group
      |> Benchee.relative_statistics()
      |> Benchee.Formatters.Console.format(options)
    end)
  end

  @impl true
  defdelegate write(output, options), to: Benchee.Formatters.Console
end
