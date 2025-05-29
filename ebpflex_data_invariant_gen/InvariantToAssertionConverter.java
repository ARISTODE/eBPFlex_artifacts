import java.io.*;
import java.util.*;
import java.util.regex.*;

/**
 * Converts Daikon invariants to Java assertions.
 * This tool parses invariant output and generates assertion methods.
 */
public class InvariantToAssertionConverter {
    
    private static final Pattern PPT_PATTERN = Pattern.compile("^=+$");
    private static final Pattern ENTER_EXIT_PATTERN = Pattern.compile("(.*):::(ENTER|EXIT\\d*)");
    private static final Pattern OLD_VAR_PATTERN = Pattern.compile("\\\\old\\((\\w+)\\)");
    private static final Pattern RESULT_PATTERN = Pattern.compile("\\\\result");
    
    private Map<String, List<String>> preconditions = new HashMap<>();
    private Map<String, List<String>> postconditions = new HashMap<>();
    
    public void parseInvariantFile(String filename) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(filename));
        String line;
        String currentPpt = null;
        boolean isEnter = false;
        List<String> currentInvariants = new ArrayList<>();
        
        while ((line = reader.readLine()) != null) {
            line = line.trim();
            
            if (PPT_PATTERN.matcher(line).matches()) {
                // Save previous invariants if any
                if (currentPpt != null && !currentInvariants.isEmpty()) {
                    if (isEnter) {
                        preconditions.put(currentPpt, new ArrayList<>(currentInvariants));
                    } else {
                        postconditions.put(currentPpt, new ArrayList<>(currentInvariants));
                    }
                }
                currentInvariants.clear();
                continue;
            }
            
            Matcher pptMatcher = ENTER_EXIT_PATTERN.matcher(line);
            if (pptMatcher.matches()) {
                currentPpt = pptMatcher.group(1);
                isEnter = pptMatcher.group(2).equals("ENTER");
                continue;
            }
            
            // Collect invariant
            if (!line.isEmpty() && currentPpt != null) {
                currentInvariants.add(line);
            }
        }
        
        // Don't forget the last set
        if (currentPpt != null && !currentInvariants.isEmpty()) {
            if (isEnter) {
                preconditions.put(currentPpt, new ArrayList<>(currentInvariants));
            } else {
                postconditions.put(currentPpt, new ArrayList<>(currentInvariants));
            }
        }
        
        reader.close();
    }
    
    public void generateAssertionClass(String outputFile) throws IOException {
        PrintWriter writer = new PrintWriter(new FileWriter(outputFile));
        
        writer.println("/**");
        writer.println(" * Auto-generated assertion class from Daikon invariants");
        writer.println(" * Generated on: " + new Date());
        writer.println(" */");
        writer.println("public class GeneratedAssertions {");
        writer.println();
        
        // Generate helper methods
        writer.println("    // Helper methods");
        writer.println("    private static boolean isPowerOfTwo(int n) {");
        writer.println("        return n > 0 && (n & (n - 1)) == 0;");
        writer.println("    }");
        writer.println();
        
        // Process each program point
        Set<String> allPpts = new HashSet<>();
        allPpts.addAll(preconditions.keySet());
        allPpts.addAll(postconditions.keySet());
        
        for (String ppt : allPpts) {
            String className = sanitizeClassName(ppt);
            writer.println("    /**");
            writer.println("     * Assertions for " + ppt);
            writer.println("     */");
            writer.println("    public static class " + className + " {");
            
            // Generate precondition assertions
            if (preconditions.containsKey(ppt)) {
                writer.println();
                writer.println("        public static void assertPreconditions(" + generateParameterList(ppt, true) + ") {");
                for (String inv : preconditions.get(ppt)) {
                    String assertion = convertToAssertion(inv, true);
                    if (assertion != null) {
                        writer.println("            " + assertion);
                    }
                }
                writer.println("        }");
            }
            
            // Generate postcondition assertions
            if (postconditions.containsKey(ppt)) {
                writer.println();
                writer.println("        public static void assertPostconditions(" + generateParameterList(ppt, false) + ") {");
                for (String inv : postconditions.get(ppt)) {
                    String assertion = convertToAssertion(inv, false);
                    if (assertion != null) {
                        writer.println("            " + assertion);
                    }
                }
                writer.println("        }");
            }
            
            writer.println("    }");
            writer.println();
        }
        
        writer.println("}");
        writer.close();
    }
    
    private String sanitizeClassName(String ppt) {
        // Convert program point name to valid Java class name
        return ppt.replaceAll("[^a-zA-Z0-9]", "_")
                  .replaceAll("^_+", "")
                  .replaceAll("_+$", "");
    }
    
    private String generateParameterList(String ppt, boolean isPrecondition) {
        // This is a simplified version - in practice, you'd need to analyze
        // the invariants to determine the actual parameters
        Set<String> params = new TreeSet<>();
        List<String> invs = isPrecondition ? preconditions.get(ppt) : postconditions.get(ppt);
        
        if (invs != null) {
            for (String inv : invs) {
                // Extract variable names from invariants
                Pattern varPattern = Pattern.compile("\\b(\\w+)\\b");
                Matcher matcher = varPattern.matcher(inv);
                while (matcher.find()) {
                    String var = matcher.group(1);
                    if (!var.matches("\\d+") && !isKeyword(var)) {
                        params.add(var);
                    }
                }
            }
        }
        
        StringBuilder paramList = new StringBuilder();
        for (String param : params) {
            if (paramList.length() > 0) paramList.append(", ");
            paramList.append("int ").append(param);
        }
        
        return paramList.toString();
    }
    
    private boolean isKeyword(String word) {
        Set<String> keywords = new HashSet<>(Arrays.asList(
            "assert", "true", "false", "null", "void", "int", "long", 
            "double", "float", "boolean", "char", "byte", "short",
            "daikon", "tools", "runtimechecker", "Runtime", "isPowerOfTwo",
            "old", "result"
        ));
        return keywords.contains(word);
    }
    
    private String convertToAssertion(String invariant, boolean isPrecondition) {
        // Skip empty lines
        if (invariant.trim().isEmpty()) return null;
        
        // Handle special patterns
        String assertion = invariant;
        
        // Convert \old(var) to oldVar for postconditions
        if (!isPrecondition) {
            assertion = OLD_VAR_PATTERN.matcher(assertion).replaceAll("old$1");
        }
        
        // Convert \result to result
        assertion = RESULT_PATTERN.matcher(assertion).replaceAll("result");
        
        // Handle isPowerOfTwo
        if (assertion.contains("daikon.tools.runtimechecker.Runtime.isPowerOfTwo")) {
            assertion = assertion.replace("daikon.tools.runtimechecker.Runtime.isPowerOfTwo", "isPowerOfTwo");
        }
        
        // Create the assertion statement
        return "assert " + assertion + " : \"Invariant violated: " + 
               invariant.replace("\"", "\\\"") + "\";";
    }
    
    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: java InvariantToAssertionConverter <input_invariant_file> <output_java_file>");
            System.exit(1);
        }
        
        try {
            InvariantToAssertionConverter converter = new InvariantToAssertionConverter();
            converter.parseInvariantFile(args[0]);
            converter.generateAssertionClass(args[1]);
            System.out.println("Successfully generated assertions in " + args[1]);
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}