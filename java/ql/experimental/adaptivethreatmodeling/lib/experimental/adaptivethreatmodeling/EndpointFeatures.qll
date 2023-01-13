/**
 * For internal use only.
 *
 * Extracts data about the database for use in adaptive threat modeling (ATM).
 */

private import java
private import semmle.code.java.dataflow.DataFlow::DataFlow as DataFlow
private import FeaturizationConfig

/**
 * Gets the value of the token-based feature named `featureName` for the endpoint `endpoint`.
 *
 * This is a single string containing a space-separated list of tokens.
 */
private string getTokenFeature(DataFlow::Node endpoint, string featureName) {
  // Performance optimization: Restrict feature extraction to endpoints we've explicitly asked to featurize.
  endpoint = any(FeaturizationConfig cfg).getAnEndpointToFeaturize() and
  exists(EndpointFeature f | f.getName() = featureName and result = f.getValue(endpoint)) and
  featureName = getASupportedFeatureName()
}

/** Get a name of a supported generic token-based feature. */
string getASupportedFeatureName() { result = any(EndpointFeature f).getName() }

/**
 * Generic token-based features for ATM.
 *
 * This predicate holds if the generic token-based feature named `featureName` has the value
 * `featureValue` for the endpoint `endpoint`.
 */
predicate tokenFeatures(DataFlow::Node endpoint, string featureName, string featureValue) {
  // Performance optimization: Restrict feature extraction to endpoints we've explicitly asked to featurize.
  endpoint = any(FeaturizationConfig cfg).getAnEndpointToFeaturize() and
  featureValue = getTokenFeature(endpoint, featureName)
}

/**
 * See EndpointFeature
 */
private newtype TEndpointFeature =
  TFeature1() or
  TFeature2() or
  TFeature3()

/**
 * An implementation of an endpoint feature: defines feature-name/value tuples for use in ML.
 */
abstract class EndpointFeature extends TEndpointFeature {
  /**
   * Gets the name of the feature. Used by the ML model.
   * Names are coupled to models: changing the name of a feature requires retraining the model.
   */
  abstract string getName();

  /**
   * Gets the value of the feature. Used by the ML model.
   * Models are trained based on feature values, so changing the value of a feature requires retraining the model.
   */
  abstract string getValue(DataFlow::Node endpoint);

  string toString() { result = this.getName() }
}

/**
 * Feature 1 implementation
 */
class Feature1 extends EndpointFeature, TFeature1 {
  override string getName() { result = "f1_name" }

  override string getValue(DataFlow::Node endpoint) { result = "f1_value" }
}

/**
 * Feature 2 implementation
 */
class Feature2 extends EndpointFeature, TFeature2 {
  override string getName() { result = "f2_name" }

  override string getValue(DataFlow::Node endpoint) { result = "f2_value" }
}
